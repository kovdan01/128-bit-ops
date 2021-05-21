#include <libakrypt.h>

#include <benchmark/benchmark.h>

#include <iostream>

namespace bm = benchmark;

#define INIT_X                                                      \
    ak_uint64 x[2];                                                 \
    ak_mpzn_set_hexstr(x, 2, "b0f093b8949426d38be409bea434edf9");   \

#define INIT_Y                                                      \
    ak_uint64 y[2];                                                 \
    ak_mpzn_set_hexstr(y, 2, "c849ac39dbd6d46ff0556e673ca07a73");   \

#define INIT_X_Y                                                    \
    INIT_X;                                                         \
    INIT_Y;                                                         \

#define INIT_P                                                      \
    ak_uint64 p[2];                                                 \
    ak_mpzn_set_hexstr(p, 2, "dc19d1f9597ba810b404988344eb5d41");   \

#define INIT_X_Y_P                                                  \
    INIT_X_Y;                                                       \
    INIT_P;                                                         \

static void sum_128(bm::State& state)
{
    INIT_X_Y;
    ak_mpzn128 sum;

    for (auto _ : state)
    {
        ak_uint64 ans = ak_128_add(sum, x, y);
        bm::DoNotOptimize(ans);
    }
}
BENCHMARK(sum_128);

static void sum_common(bm::State& state)
{
    INIT_X_Y;
    ak_mpzn128 sum;

    for (auto _ : state)
    {
        ak_uint64 ans = ak_mpzn_add(sum, x, y, 2);
        bm::DoNotOptimize(ans);
    }
}
BENCHMARK(sum_common);

static void sum_modulo_128(bm::State& state)
{
    INIT_X_Y_P;
    ak_mpzn128 sum;

    for (auto _ : state)
    {
        ak_128_add_mod(sum, x, y, p);
        bm::DoNotOptimize(sum);
    }
}
BENCHMARK(sum_modulo_128);

static void sum_modulo_common(bm::State& state)
{
    INIT_X_Y_P;
    ak_mpzn128 sum;

    for (auto _ : state)
    {
        ak_mpzn_add_montgomery(sum, x, y, p, ak_mpzn128_size);
        bm::DoNotOptimize(sum);
    }
}
BENCHMARK(sum_modulo_common);

static void sub_128(bm::State& state)
{
    INIT_X_Y;
    ak_mpzn128 sub;

    for (auto _ : state)
    {
        ak_uint64 ans = ak_128_sub(sub, x, y);
        bm::DoNotOptimize(ans);
    }
}
BENCHMARK(sub_128);

static void sub_common(bm::State& state)
{
    INIT_X_Y;
    ak_mpzn128 sub;

    for (auto _ : state)
    {
        ak_uint64 ans = ak_mpzn_sub(sub, x, y, ak_mpzn128_size);
        bm::DoNotOptimize(ans);
    }
}
BENCHMARK(sub_common);

static void sub_modulo_128(bm::State& state)
{
    INIT_X_Y_P;
    ak_mpzn128 sub;

    for (auto _ : state)
    {
        ak_128_sub_mod(sub, x, y, p);
        bm::DoNotOptimize(sub);
    }
}
BENCHMARK(sub_modulo_128);

static void mul_128(bm::State& state)
{
    INIT_X_Y;
    ak_mpzn256 mul;

    for (auto _ : state)
    {
        ak_128_mul(mul, x, y);
        bm::DoNotOptimize(mul);
    }
}
BENCHMARK(mul_128);

static void mul_common(bm::State& state)
{
    INIT_X_Y;
    ak_mpzn256 mul;

    for (auto _ : state)
    {
        ak_mpzn_mul(mul, x, y, ak_mpzn128_size);
        bm::DoNotOptimize(mul);
    }
}
BENCHMARK(mul_common);

static void mul_modulo_128(bm::State& state)
{
    INIT_X_Y_P;
    ak_mpzn128 mul;

    for (auto _ : state)
    {
        ak_128_mul_mod(mul, x, y, p);
        bm::DoNotOptimize(mul);
    }
}
BENCHMARK(mul_modulo_128);

static void mul_montgomery_128(bm::State& state)
{
    INIT_X_Y_P;

    ak_montgomery_context_128 ctx;
    ak_mpzn_set(ctx.p, p, ak_mpzn128_size);
    ak_128_montgomery_init(&ctx);

    ak_mpzn128 x_mont, y_mont;
    ak_128_to_montgomery(x_mont, x, &ctx);
    ak_128_to_montgomery(y_mont, y, &ctx);

    ak_mpzn128 mul;

    for (auto _ : state)
    {
        ak_128_montgomery_mul(mul, x_mont, y_mont, &ctx);
        bm::DoNotOptimize(mul);
    }
}
BENCHMARK(mul_montgomery_128);

static void mul_montgomery_common(bm::State& state)
{
    INIT_X_Y_P;

    ak_montgomery_context_128 ctx;
    ak_mpzn_set(ctx.p, p, ak_mpzn128_size);
    ak_128_montgomery_init(&ctx);

    ak_mpzn128 x_mont, y_mont;
    ak_128_to_montgomery(x_mont, x, &ctx);
    ak_128_to_montgomery(y_mont, y, &ctx);

    ak_mpzn128 mul;

    for (auto _ : state)
    {
        ak_mpzn_mul_montgomery(mul, x_mont, y_mont, ctx.p, ctx.v[0], ak_mpzn128_size);
        bm::DoNotOptimize(mul);
    }
}
BENCHMARK(mul_montgomery_common);

static void inverse_128(bm::State& state)
{
    INIT_X;
    INIT_P;
    ak_mpzn128 inverse;

    for (auto _ : state)
    {
        ak_128_inverse(inverse, x, p);
        bm::DoNotOptimize(inverse);
    }
}
BENCHMARK(inverse_128);

static void point_add_128(bm::State& state)
{
    INIT_P;

    point128 a, b, c;
    ak_mpzn_set_hexstr(a.x, ak_mpzn128_size, "b0f093b8949426d38be409bea434edf9");
    ak_mpzn_set_hexstr(a.y, ak_mpzn128_size, "c849ac39dbd6d46ff0556e673ca07a73");

    ak_mpzn_set_hexstr(b.x, ak_mpzn128_size, "b5b677bdd775788e3539f3856cb52f3f");
    ak_mpzn_set_hexstr(b.y, ak_mpzn128_size, "d4ff68d2a3f87a55ff8f5658313b4d9a");

    for (auto _ : state)
    {
        ak_128_point_add(&c, &a, &b, p);
        bm::DoNotOptimize(c);
    }
}
BENCHMARK(point_add_128);

int main(int argc, char** argv) try
{
    bm::Initialize(&argc, argv);
    bm::RunSpecifiedBenchmarks();
}
catch (const std::exception& e)
{
    std::cerr << e.what() << '\n';
    return 1;
}
