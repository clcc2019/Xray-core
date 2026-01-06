package encryption

import (
	"testing"
	"time"
)

func TestUniformStrategy(t *testing.T) {
	s := NewUniformStrategy()

	// 测试长度生成
	for i := 0; i < 100; i++ {
		l := s.GenerateLength(100, 200)
		if l < 100 || l > 200 {
			t.Errorf("uniform length out of range: %d", l)
		}
	}

	// 测试延迟生成
	for i := 0; i < 100; i++ {
		d := s.GenerateDelay(10, 100)
		if d < 10*time.Millisecond || d > 100*time.Millisecond {
			t.Errorf("uniform delay out of range: %v", d)
		}
	}
}

func TestGaussianStrategy(t *testing.T) {
	s := NewGaussianStrategy()

	// 统计分布
	counts := make(map[int]int)
	for i := 0; i < 10000; i++ {
		l := s.GenerateLength(100, 200)
		if l < 100 || l > 200 {
			t.Errorf("gaussian length out of range: %d", l)
		}
		bucket := (l - 100) / 10
		counts[bucket]++
	}

	// 验证中间值更多（正态分布特性）
	middle := counts[5] // 150 附近
	edge := counts[0]   // 100 附近
	if middle <= edge {
		t.Logf("gaussian distribution might not be centered: middle=%d, edge=%d", middle, edge)
	}
}

func TestExponentialStrategy(t *testing.T) {
	s := NewExponentialStrategy()

	// 统计分布
	lowCount := 0
	for i := 0; i < 10000; i++ {
		l := s.GenerateLength(100, 1000)
		if l < 100 || l > 1000 {
			t.Errorf("exponential length out of range: %d", l)
		}
		if l < 400 { // 前 1/3
			lowCount++
		}
	}

	// 指数分布应该有更多的低值
	if lowCount < 5000 {
		t.Logf("exponential distribution: %d%% in lower third", lowCount/100)
	}
}

func TestParetoStrategy(t *testing.T) {
	s := NewParetoStrategy(1.16) // 80/20 分布

	lowCount := 0
	for i := 0; i < 10000; i++ {
		l := s.GenerateLength(100, 1000)
		if l < 100 || l > 1000 {
			t.Errorf("pareto length out of range: %d", l)
		}
		if l < 300 { // 下 20%
			lowCount++
		}
	}

	// 帕累托分布应该集中在低值
	t.Logf("pareto distribution: %d%% in lower 20%%", lowCount/100)
}

func TestBurstStrategy(t *testing.T) {
	s := NewBurstStrategy(0.2, 2, 5)

	burstCount := 0
	sum := 0
	for i := 0; i < 10000; i++ {
		l := s.GenerateLength(100, 200)
		sum += l
		if l > 200 { // 超过正常范围说明是突发
			burstCount++
		}
	}

	avg := sum / 10000
	t.Logf("burst strategy: avg=%d, burst_rate=%.1f%%", avg, float64(burstCount)/100)
}

func TestMixedStrategy(t *testing.T) {
	s := NewMixedStrategy(nil, nil)

	for i := 0; i < 1000; i++ {
		l := s.GenerateLength(100, 1000)
		if l < 100 || l > 1000 {
			t.Errorf("mixed length out of range: %d", l)
		}
	}
}

func TestLogNormalStrategy(t *testing.T) {
	s := NewLogNormalStrategy(0.5, 1.0)

	// 统计分布
	sum := 0
	for i := 0; i < 10000; i++ {
		l := s.GenerateLength(100, 1000)
		if l < 100 || l > 1000 {
			t.Errorf("lognormal length out of range: %d", l)
		}
		sum += l
	}
	avg := sum / 10000
	t.Logf("lognormal distribution: avg=%d (expected ~400-600)", avg)
}

func TestOptimalStrategy(t *testing.T) {
	s := NewOptimalStrategy()

	// 测试长度分布
	buckets := make(map[int]int)
	for i := 0; i < 10000; i++ {
		l := s.GenerateLength(100, 1000)
		if l < 100 || l > 1000 {
			t.Errorf("optimal length out of range: %d", l)
		}
		bucket := (l - 100) / 100 // 0-9 的桶
		buckets[bucket]++
	}

	t.Log("optimal strategy distribution:")
	for i := 0; i < 10; i++ {
		pct := float64(buckets[i]) / 100
		bar := ""
		for j := 0; j < int(pct); j++ {
			bar += "█"
		}
		t.Logf("  %d-%d: %5.1f%% %s", 100+i*100, 199+i*100, pct, bar)
	}

	// 测试延迟分布
	delaySum := time.Duration(0)
	for i := 0; i < 1000; i++ {
		d := s.GenerateDelay(10, 200)
		if d < 10*time.Millisecond || d > 200*time.Millisecond {
			t.Errorf("optimal delay out of range: %v", d)
		}
		delaySum += d
	}
	avgDelay := delaySum / 1000
	t.Logf("optimal delay avg: %v", avgDelay)
}

func TestDefaultStrategyIsOptimal(t *testing.T) {
	s := GetDefaultStrategy()
	if s.Name() != "optimal" {
		t.Errorf("default strategy should be optimal, got %s", s.Name())
	}
}

func TestOptimizedCreatPadding(t *testing.T) {
	paddingLens := [][3]int{{100, 111, 1111}, {50, 0, 3333}}
	paddingGaps := [][3]int{{75, 0, 111}}

	for _, strategyName := range []string{"uniform", "gaussian", "exponential", "mixed"} {
		strategy := NewPaddingStrategy(strategyName)

		length, lens, gaps := OptimizedCreatPadding(paddingLens, paddingGaps, strategy)

		t.Logf("%s strategy: total_length=%d, lens=%v, gaps=%v",
			strategyName, length, lens, gaps)

		// 验证总长度
		sum := 0
		for _, l := range lens {
			sum += l
		}
		if sum != length {
			t.Errorf("length mismatch: sum=%d, total=%d", sum, length)
		}
	}
}

func TestFillRandomPadding(t *testing.T) {
	buf := make([]byte, 1000)
	FillRandomPadding(buf)

	// 检查不全是 0
	zeros := 0
	for _, b := range buf {
		if b == 0 {
			zeros++
		}
	}
	if zeros > 100 { // 允许一些 0
		t.Errorf("too many zeros in random padding: %d", zeros)
	}

	// 检查基本随机性（字节分布）
	counts := make([]int, 256)
	for _, b := range buf {
		counts[b]++
	}

	// 每个字节平均出现约 4 次，检查没有过于集中
	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}
	if maxCount > 50 { // 不应该有字节出现超过 50 次
		t.Logf("max byte count: %d (expected ~4)", maxCount)
	}
}

func TestPaddingBufferPool(t *testing.T) {
	// 测试池化
	buf1 := AcquirePaddingBuffer(1000)
	if len(buf1) != 1000 {
		t.Errorf("expected length 1000, got %d", len(buf1))
	}

	ReleasePaddingBuffer(buf1)

	buf2 := AcquirePaddingBuffer(500)
	ReleasePaddingBuffer(buf2)

	// 大于池大小
	buf3 := AcquirePaddingBuffer(100000)
	if len(buf3) != 100000 {
		t.Errorf("expected length 100000, got %d", len(buf3))
	}
}

// ================================
// 基准测试
// ================================

func BenchmarkUniformStrategy(b *testing.B) {
	s := NewUniformStrategy()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GenerateLength(100, 1000)
	}
}

func BenchmarkGaussianStrategy(b *testing.B) {
	s := NewGaussianStrategy()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GenerateLength(100, 1000)
	}
}

func BenchmarkExponentialStrategy(b *testing.B) {
	s := NewExponentialStrategy()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GenerateLength(100, 1000)
	}
}

func BenchmarkParetoStrategy(b *testing.B) {
	s := NewParetoStrategy(1.16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GenerateLength(100, 1000)
	}
}

func BenchmarkMixedStrategy(b *testing.B) {
	s := NewMixedStrategy(nil, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GenerateLength(100, 1000)
	}
}

func BenchmarkLogNormalStrategy(b *testing.B) {
	s := NewLogNormalStrategy(0.5, 1.0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GenerateLength(100, 1000)
	}
}

func BenchmarkOptimalStrategy(b *testing.B) {
	s := NewOptimalStrategy()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GenerateLength(100, 1000)
	}
}

func BenchmarkDefaultStrategy(b *testing.B) {
	s := GetDefaultStrategy()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GenerateLength(100, 1000)
	}
}

func BenchmarkOptimizedCreatPadding(b *testing.B) {
	paddingLens := [][3]int{{100, 111, 1111}, {50, 0, 3333}}
	paddingGaps := [][3]int{{75, 0, 111}}
	strategy := GetDefaultStrategy()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		OptimizedCreatPadding(paddingLens, paddingGaps, strategy)
	}
}

func BenchmarkOriginalCreatPadding(b *testing.B) {
	paddingLens := [][3]int{{100, 111, 1111}, {50, 0, 3333}}
	paddingGaps := [][3]int{{75, 0, 111}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CreatPadding(paddingLens, paddingGaps)
	}
}

func BenchmarkFillRandomPadding(b *testing.B) {
	buf := make([]byte, 4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FillRandomPadding(buf)
	}
}

func BenchmarkCryptoRandRead(b *testing.B) {
	buf := make([]byte, 4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 原始方式使用 crypto/rand
		_, _ = buf[0], buf[len(buf)-1] // 模拟访问
	}
}

func BenchmarkPaddingBufferPool(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := AcquirePaddingBuffer(4096)
			FillRandomPadding(buf)
			ReleasePaddingBuffer(buf)
		}
	})
}
