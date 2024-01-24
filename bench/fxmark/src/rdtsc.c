// SPDX-License-Identifier: MIT
#include "rdtsc.h"

#include <err.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

uint64_t rdtsc_overhead(double *stddev_out)
{
    enum { SAMPLES = 512 };
    uint64_t samples[SAMPLES];
    double mean, stddev;

    for (int attempt = 0; attempt < 10; ++attempt) {
        uint64_t sum = 0;
        for (size_t i = 0; i < SAMPLES; ++i) {
            uint64_t start = rdtsc_beg();
            uint64_t end = rdtsc_end();
            samples[i] = end - start;
            sum += samples[i];
        }

        // Compute stddev
        mean = (double)sum / SAMPLES;
        double variance = 0;
        for (size_t i = 0; i < SAMPLES; ++i)
            variance += (samples[i] - mean) * (samples[i] - mean);
        variance /= SAMPLES;
        stddev = sqrt(variance);

        if (stddev < 5)
            break;
    }

    if (stddev_out)
        *stddev_out = stddev;
    uint64_t min = samples[0];
    for (size_t i = 0; i < SAMPLES; ++i)
        if (samples[i] < min)
            min = samples[i];
    return min;
}

uint64_t cpu_freq(void)
{
    uint64_t hz = 0;

    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp)
        err(1, "failed to open cpuinfo");

    char *line = NULL;
    size_t len = 0;

    while (getline(&line, &len, fp) != -1) {
        double mhz;
        if (sscanf(line, "cpu MHz         : %lf", &mhz) == 1)
            hz = (uint64_t) (mhz * 1000 * 1000);
    }
    free(line);

    return hz;
}

uint64_t cpu_freq_measured(void)
{
    uint64_t beg, end;

    beg = rdtsc_beg();
    sleep(1);
    end = rdtsc_beg();

    return end - beg;
}

#ifdef MAIN
int main(int argc, char *argv[])
{
    uint64_t hz1 = cpu_freq();
    uint64_t hz2 = cpu_freq_measured();

    printf("hz1 = %llu\n", (unsigned long long)hz1);
    printf("hz2 = %llu\n", (unsigned long long)hz2);
    printf("%f %%\n", (double)(hz2 - hz1) / hz1 * 100.0);

    return 0;
}
#endif
