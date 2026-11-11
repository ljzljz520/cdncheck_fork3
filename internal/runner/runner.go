package runner

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
	iputils "github.com/projectdiscovery/utils/ip"
)

type Runner struct {
	options   *Options
	cdnclient *cdncheck.Client
	aurora    *aurora.Aurora
	writer    *OutputWriter
}

func NewRunner(options *Options) *Runner {
	standardWriter := aurora.NewAurora(!options.NoColor)
	client, err := cdncheck.NewWithOpts(options.MaxRetries, options.Resolvers)
	if err != nil {
		gologger.Fatal().Msgf("failed to create cdncheck client: %v", err)
	}
	runner := &Runner{
		options:   options,
		cdnclient: client,
		aurora:    &standardWriter,
	}
	return runner
}

func (r *Runner) Run() error {
	err := r.configureOutput()
	if err != nil {
		return errors.Wrap(err, "could not configure output")
	}
	defer r.writer.Close()
	threads := r.options.Threads
	if threads <= 0 {
		threads = 1
	}
	output := make(chan Output, threads)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go r.process(output, wg)
	wg.Add(1)
	go r.waitForData(output, wg)
	wg.Wait()
	return nil
}

func (r *Runner) SetWriter(writer io.Writer) error {
	outputWriter, err := NewOutputWriter()
	if err != nil {
		return err
	}
	outputWriter.AddWriters(writer)
	r.writer = outputWriter
	return nil
}

func (r *Runner) process(output chan Output, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(output)

	threads := r.options.Threads
	if threads <= 0 {
		threads = 1
	}

	tasks := make(chan string, threads)
	var workerWg sync.WaitGroup

	for i := 0; i < threads; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for item := range tasks {
				r.processInputItemSingle(item, output)
			}
		}()
	}

	sendItem := func(input string) {
		if _, ipRange, _ := net.ParseCIDR(input); ipRange != nil {
			cidrInputs, err := mapcidr.IPAddressesAsStream(input)
			if err != nil {
				if r.options.Verbose {
					gologger.Error().Msgf("Could not parse cidr %s: %s", input, err)
				}
				return
			}
			for cidr := range cidrInputs {
				tasks <- cidr
			}
		} else {
			tasks <- input
		}
	}

	for _, target := range r.options.Inputs {
		sendItem(target)
	}
	if r.options.HasStdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				sendItem(text)
			}
		}
	}

	close(tasks)
	workerWg.Wait()
}

func (r *Runner) waitForData(output chan Output, wg *sync.WaitGroup) {
	defer wg.Done()
	var cdnCount, wafCount, cloudCount, undeterminedCount int
	for receivedData := range output {
		// Undetermined inputs follow the same three-state contract through
		// the callback but are never written as conclusive output.
		if receivedData.Status == cdncheck.DomainStatusUndetermined {
			undeterminedCount++
			if r.options.OnResult != nil {
				r.options.OnResult(receivedData)
			}
			continue
		}

		if receivedData.Cdn {
			cdnCount++
		} else if receivedData.Waf {
			wafCount++
		} else if receivedData.Cloud {
			cloudCount++
		}

		if r.options.OnResult != nil {
			r.options.OnResult(receivedData)
		}

		if r.options.Json {
			r.writer.WriteJSON(receivedData)
		} else if r.options.Response && !r.options.Exclude {
			r.writer.WriteString(receivedData.String())
		} else {
			r.writer.WriteString(receivedData.Input)
		}
	}

	// show undetermined summary so batch runs account for skipped inputs
	if undeterminedCount > 0 {
		message := fmt.Sprintf("Skipped %d undetermined input(s) with incomplete resolution", undeterminedCount)
		if !r.options.Verbose {
			message += " (use -verbose for failure reasons)"
		}
		gologger.Info().Msg(message)
	}

	// show summary to user
	sw := *r.aurora
	if (cdnCount + wafCount + cloudCount) < 1 {
		gologger.Info().Msgf("No results found.")
		return
	}
	var builder strings.Builder
	_, _ = fmt.Fprintf(&builder, "Found result: %v", (cdnCount + cloudCount + wafCount))
	builder.WriteString(" (")
	if cdnCount > 0 {
		_, _ = fmt.Fprintf(&builder, "%s %v", sw.BrightBlue("CDN:").String(), cdnCount)
	}
	if cloudCount > 0 {
		if cdnCount > 0 {
			builder.WriteString(", ")
		}
		_, _ = fmt.Fprintf(&builder, "%s %v", sw.BrightGreen("CLOUD:").String(), cloudCount)
	}
	if wafCount > 0 {
		if cdnCount > 0 || cloudCount > 0 {
			builder.WriteString(", ")
		}
		_, _ = fmt.Fprintf(&builder, "%s %v", sw.Yellow("WAF:").String(), wafCount)
	}
	builder.WriteString(")")
	gologger.Info().Msg(builder.String())
}

func (r *Runner) configureOutput() error {
	if r.writer != nil {
		return nil
	}
	outputWriter, err := NewOutputWriter()
	if err != nil {
		return err
	}
	if r.options.OnResult != nil {
		r.writer = outputWriter
		return nil
	}
	outputWriter.AddWriters(os.Stdout)
	if r.options.Output != "" {
		outputFile, err := os.Create(r.options.Output)
		if err != nil {
			return err
		}
		outputWriter.AddWriters(outputFile)
	}
	r.writer = outputWriter
	return nil
}

func (r *Runner) processInputItemSingle(item string, output chan Output) {
	data := Output{
		aurora:    r.aurora,
		Input:     item,
		Timestamp: time.Now(),
	}

	if iputils.IsIP(item) {
		r.evaluateIP(item, &data)
	} else {
		r.evaluateDomain(item, &data)
	}

	// Undetermined inputs never produce conclusive output: they are surfaced
	// through the result callback and verbose diagnostics, but never written
	// as exclusion targets or detection results.
	if data.Status == cdncheck.DomainStatusUndetermined {
		if r.options.Verbose {
			gologger.Warning().Msgf("Could not determine provider for %s: %s", item, strings.Join(data.Reasons, "; "))
		}
		output <- data
		return
	}

	if r.options.Exclude {
		// Only confirmed misses backed by a usable address enter exclusion
		// output; matched and undetermined inputs are both withheld.
		if data.Status == cdncheck.DomainStatusMissed {
			output <- data
		}
		return
	}

	// Outside exclusion mode only matched items are emitted, preserving the
	// historical detection output.
	if data.Status != cdncheck.DomainStatusMatched {
		return
	}
	if skipped := filterIP(r.options, data); skipped {
		return
	}
	if matched := matchIP(r.options, data); !matched {
		return
	}
	switch {
	case r.options.Cdn && data.itemType == "cdn", r.options.Cloud && data.itemType == "cloud", r.options.Waf && data.itemType == "waf":
		output <- data
	case !r.options.Cdn && !r.options.Waf && !r.options.Cloud:
		output <- data
	}
}

// evaluateIP classifies a raw IP input. An IP is itself a usable address, so
// a failed range lookup is the only undetermined case; every non-matching IP
// is a confirmed miss.
func (r *Runner) evaluateIP(item string, data *Output) {
	matched, provider, itemType, err := r.cdnclient.Check(net.ParseIP(item))
	data.IP = item
	if err != nil {
		data.Status = cdncheck.DomainStatusUndetermined
		data.Reasons = []string{fmt.Sprintf("ip check failed: %s", err.Error())}
		return
	}
	if matched {
		r.markMatched(data, itemType, provider)
		return
	}
	data.Status = cdncheck.DomainStatusMissed
}

// evaluateDomain runs the detailed three-state domain identification and maps
// its contract onto the runner Output.
func (r *Runner) evaluateDomain(item string, data *Output) {
	result := r.cdnclient.CheckDomainWithFallbackDetailed(item)

	data.Status = result.Status
	data.IP = result.IP
	data.Reasons = result.Reasons
	if result.AddressQuery.Stage != "" {
		addressQuery := result.AddressQuery
		data.AddressQuery = &addressQuery
	}
	if result.CNAMEQuery.Stage != "" {
		cnameQuery := result.CNAMEQuery
		data.CNAMEQuery = &cnameQuery
	}
	if result.Matched {
		r.markMatched(data, result.ItemType, result.Provider)
	}
}

func (r *Runner) markMatched(data *Output, itemType, provider string) {
	data.Status = cdncheck.DomainStatusMatched
	data.itemType = itemType
	switch itemType {
	case "cdn":
		data.Cdn = true
		data.CdnName = provider
	case "cloud":
		data.Cloud = true
		data.CloudName = provider
	case "waf":
		data.Waf = true
		data.WafName = provider
	}
}

func matchIP(options *Options, data Output) bool {
	if len(options.MatchCdn) == 0 && len(options.MatchCloud) == 0 && len(options.MatchWaf) == 0 {
		return true
	}
	if len(options.MatchCdn) > 0 && data.itemType == "cdn" {
		matched := false
		for _, filter := range options.MatchCdn {
			if filter == data.CdnName {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	if len(options.MatchCloud) > 0 && data.itemType == "cloud" {
		matched := false
		for _, filter := range options.MatchCloud {
			if filter == data.CloudName {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	if len(options.MatchWaf) > 0 && data.itemType == "waf" {
		matched := false
		for _, filter := range options.MatchWaf {
			if filter == data.WafName {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func filterIP(options *Options, data Output) bool {
	if len(options.FilterCdn) == 0 && len(options.FilterCloud) == 0 && len(options.FilterWaf) == 0 {
		return false
	}
	if len(options.FilterCdn) > 0 && data.itemType == "cdn" {
		for _, filter := range options.FilterCdn {
			if filter == data.CdnName {
				return true
			}
		}
	}
	if len(options.FilterCloud) > 0 && data.itemType == "cloud" {
		for _, filter := range options.FilterCloud {
			if filter == data.CloudName {
				return true
			}
		}
	}
	if len(options.FilterWaf) > 0 && data.itemType == "waf" {
		for _, filter := range options.FilterWaf {
			if filter == data.WafName {
				return true
			}
		}
	}
	return false
}
