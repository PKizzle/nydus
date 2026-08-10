// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/dragonflyoss/nydus/smoke/tests/tool/test"
	"github.com/google/uuid"
)

// Environment Requirement: Containerd, nerdctl >= 0.22, nydus-snapshotter, nydusd, nydus-image and nydusify.
// Prepare: setup nydus for containerd, reference: https://github.com/dragonflyoss/nydus/blob/master/docs/containerd-env-setup.md.
// TestBenchmark will dump json file(benchmark.json) which includes container e2e time, image size, read-amount and read-count.
//	Example:
//	{
//		e2e_time: 2747131
//		image_size: 2107412
//		read_amount: 121345
//		read_count: 121
//	}

type BenchmarkTestSuite struct {
	t                 *testing.T
	testImage         string
	testContainerName string
	snapshotter       string
	metric            tool.ContainerMetrics
}

func (b *BenchmarkTestSuite) TestBenchmark(t *testing.T) {
	ctx := tool.DefaultContext(b.t)
	b.snapshotter = os.Getenv("SNAPSHOTTER")
	if b.snapshotter == "" {
		b.snapshotter = "nydus"
	}

	// choose test mode
	mode := os.Getenv("BENCHMARK_MODE")
	if mode == "" {
		mode = "fs-version-6"
	}
	switch mode {
	case "oci":
	case "fs-version-6":
		ctx.Build.FSVersion = "6"
	case "zran":
		ctx.Build.OCIRef = true
	default:
		b.t.Fatalf("Benchmark don't support %s mode", mode)
	}

	// prepare benchmark image
	image := os.Getenv("BENCHMARK_TEST_IMAGE")
	if image == "" {
		image = "wordpress:6.1.1"
	} else {
		if !tool.SupportContainerImage(tool.ImageRepo(b.t, image)) {
			b.t.Fatalf("Benchmark don't support %s image ", image)
		}
	}
	targetImageSize, conversionElapsed := b.prepareImage(b.t, ctx, image)

	// run container
	b.testContainerName = uuid.NewString()
	containerMetric := tool.RunContainer(b.t, b.testImage, b.snapshotter, b.testContainerName)
	b.metric = tool.ContainerMetrics{
		E2ETime:           containerMetric.E2ETime,
		ConversionElapsed: time.Duration(conversionElapsed),
		ReadCount:         containerMetric.ReadCount,
		ReadAmountTotal:   containerMetric.ReadAmountTotal,
		ImageSize:         targetImageSize,
	}

	// save metric
	b.dumpMetric()
	t.Logf("Metric: E2ETime %d ConversionElapsed %s ReadCount %d ReadAmount %d ImageSize %d", b.metric.E2ETime, b.metric.ConversionElapsed, b.metric.ReadCount, b.metric.ReadAmountTotal, b.metric.ImageSize)
}

func (b *BenchmarkTestSuite) prepareImage(t *testing.T, ctx *tool.Context, image string) (int64, int64) {
	if b.testImage != "" {
		return 0, 0
	}

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)
	source := tool.PrepareImage(t, image)

	// Prepare options
	target := fmt.Sprintf("%s-nydus-%s", source, uuid.NewString())
	fsVersion := fmt.Sprintf("--fs-version %s", ctx.Build.FSVersion)
	logLevel := "--log-level warn"
	if ctx.Binary.NydusifyOnlySupportV5 {
		fsVersion = ""
		logLevel = ""
	}
	enableOCIRef := ""
	if ctx.Build.OCIRef {
		enableOCIRef = "--oci-ref"
	}

	convertMetricFile := fmt.Sprintf("./%s.json", uuid.NewString())
	// Convert image
	convertCmd := fmt.Sprintf("%s %s convert --source %s --target %s --nydus-image %s --work-dir %s %s %s --output-json %s",
		ctx.Binary.Nydusify, logLevel, source, target, ctx.Binary.Builder, ctx.Env.WorkDir, fsVersion, enableOCIRef, convertMetricFile)
	tool.RunWithoutOutput(t, convertCmd)
	defer func() {
		_ = os.Remove(convertMetricFile)
	}()

	metricData, err := os.ReadFile(convertMetricFile)
	if err != nil {
		t.Fatalf("can't read convert metric file %s: %v", convertMetricFile, err)
		return 0, 0
	}
	// The Rust nydusify writes a richer document than the Go tool it replaced:
	// sizes stay integers, but ConversionElapsed is a duration string ("7.234s")
	// and there are string/array members alongside (target, platforms). Decoding
	// into map[string]int64, as this did, fails on any of those.
	var convertMetric struct {
		SourceImageSize   int64  `json:"SourceImageSize"`
		TargetImageSize   int64  `json:"TargetImageSize"`
		ConversionElapsed string `json:"ConversionElapsed"`
	}
	if err := json.Unmarshal(metricData, &convertMetric); err != nil {
		// Report what was actually in the file: a schema drift here is otherwise
		// indistinguishable from nydusify never writing one.
		t.Fatalf("can't parse convert metric file %s: %v\ncontent: %s", convertMetricFile, err, metricData)
		return 0, 0
	}

	var conversionElapsed time.Duration
	if convertMetric.ConversionElapsed != "" {
		conversionElapsed, err = time.ParseDuration(convertMetric.ConversionElapsed)
		if err != nil {
			t.Fatalf("can't parse ConversionElapsed %q from %s: %v",
				convertMetric.ConversionElapsed, convertMetricFile, err)
			return 0, 0
		}
	}

	if b.snapshotter == "nydus" {
		b.testImage = target
		return convertMetric.TargetImageSize, int64(conversionElapsed)
	}
	b.testImage = source
	return convertMetric.SourceImageSize, 0
}

func (b *BenchmarkTestSuite) dumpMetric() {
	metricFileName := os.Getenv("BENCHMARK_METRIC_FILE")
	if metricFileName == "" {
		metricFileName = "benchmark.json"
	}
	file, err := os.Create(metricFileName)
	if err != nil {
		b.t.Fatalf("create benchmark metric file")
	}
	defer func() {
		_ = file.Close()
	}()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(b.metric); err != nil {
		b.t.Fatalf("write benchmark metric file")
	}
}

func TestBenchmark(t *testing.T) {
	if os.Getenv("BENCHMARK_TEST") == "" {
		t.Skip("skipping benchmark test")
	}
	test.Run(t, &BenchmarkTestSuite{t: t})
}
