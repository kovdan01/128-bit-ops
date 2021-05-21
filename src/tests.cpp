#include <libakrypt.h>

#include <catch2/catch.hpp>

TEST_CASE("128-bit test", "128")
{
    ak_mpzn128 p, x, y;
    ak_mpzn_set_hexstr(p, ak_mpzn128_size, "dc19d1f9597ba810b404988344eb5d41");
    ak_mpzn_set_hexstr(x, ak_mpzn128_size, "b0f093b8949426d38be409bea434edf9");
    ak_mpzn_set_hexstr(y, ak_mpzn128_size, "c849ac39dbd6d46ff0556e673ca07a73");

    SECTION("Arithmetic sum")
    {
        ak_mpzn128 sum_got, sum_expected;
        ak_mpzn_set_hexstr(sum_expected, ak_mpzn128_size, "793a3ff2706afb437c397825e0d5686c");
        ak_uint64 sign = ak_128_add(sum_got, x, y);
        REQUIRE(sign == 1);
        REQUIRE(ak_128_equal(sum_got, sum_expected));
    }

    SECTION("Sum modulo P")
    {
        ak_mpzn128 sum_got, sum_expected;
        ak_mpzn_set_hexstr(sum_expected, ak_mpzn128_size, "9d206df916ef5332c834dfa29bea0b2b");
        ak_128_add_mod(sum_got, x, y, p);
        REQUIRE(ak_128_equal(sum_got, sum_expected));
    }

    SECTION("Arithmetic subtraction")
    {
        ak_mpzn128 sub_got, sub_expected;
        ak_mpzn_set_hexstr(sub_expected, ak_mpzn128_size, "e8a6e77eb8bd52639b8e9b5767947386");
        ak_uint64 sign = ak_128_sub(sub_got, x, y);
        REQUIRE(sign == 1);
        REQUIRE(ak_128_equal(sub_got, sub_expected));
    }

    SECTION("Subtraction modulo P")
    {
        ak_mpzn128 sub_got, sub_expected;
        ak_mpzn_set_hexstr(sub_expected, ak_mpzn128_size, "c4c0b9781238fa744f9333daac7fd0c7");
        ak_128_sub_mod(sub_got, x, y, p);
        REQUIRE(ak_128_equal(sub_got, sub_expected));
    }

    SECTION("Arithmetic multiplication")
    {
        ak_mpzn256 mul_got, mul_expected;
        ak_mpzn_set_hexstr(mul_expected, ak_mpzn256_size, "8a6edf0bf4794ecff2d8428a6f9fbfa19fcb9767666880678cf200ef14cf90db");
        ak_128_mul(mul_got, x, y);
        REQUIRE(ak_mpzn_cmp(mul_got, mul_expected, ak_mpzn256_size) == 0);
    }

    SECTION("Multiplication modulo P")
    {
        ak_mpzn128 mul_got, mul_expected;
        ak_mpzn_set_hexstr(mul_expected, ak_mpzn128_size, "690ec8e024dde92bc6df59ee66f74961");
        ak_128_mul_mod(mul_got, x, y, p);
        REQUIRE(ak_128_equal(mul_got, mul_expected));
    }

    SECTION("Division modulo P")
    {
        ak_mpzn256 z;
        ak_mpzn_set_hexstr(z, ak_mpzn256_size, "1b0f093b8949426d38be409bea434edf9");
        ak_mpzn128 quot_got, quot_expected, mod_got, mod_expected;
        ak_mpzn_set_hexstr(quot_expected, ak_mpzn128_size, "1");
        ak_mpzn_set_hexstr(mod_expected,  ak_mpzn128_size, "d4d6c1bf3b187ec2d7df713b5f4990b8");
        ak_128_div(quot_got, mod_got, z, p);
        REQUIRE(ak_128_equal(quot_got, quot_expected));
        REQUIRE(ak_128_equal(mod_got,  mod_expected));
    }

    SECTION("Inverse modulo P")
    {
        ak_mpzn128 inverse;
        ak_128_inverse(inverse, x, p);
        ak_mpzn128 mul;
        ak_128_mul_mod(mul, x, inverse, p);
        REQUIRE(ak_128_is_one(mul));
    }

    SECTION("Montgomery")
    {
        ak_mpzn128 v_correct, r_correct, r2_correct;
        ak_mpzn_set_hexstr(v_correct, ak_mpzn128_size, "af4f33d14a6bf50b63410849fba7cd3f");
        ak_mpzn_set_hexstr(r_correct, ak_mpzn128_size, "23e62e06a68457ef4bfb677cbb14a2bf");
        ak_mpzn_set_hexstr(r2_correct, ak_mpzn128_size, "4c28f72aa4dba57ae6e8588b1000c65");

        ak_montgomery_context_128 ctx;
        ak_mpzn_set(ctx.p, p, ak_mpzn128_size);
        ak_128_montgomery_init(&ctx);

        REQUIRE(ak_128_equal(ctx.v, v_correct));
        REQUIRE(ak_128_equal(ctx.r, r_correct));
        REQUIRE(ak_128_equal(ctx.r2, r2_correct));

        ak_mpzn128 x_mont_got, x_mont_correct, y_mont_got, y_mont_correct;
        ak_mpzn_set_hexstr(x_mont_correct, ak_mpzn128_size, "12baf39bcd1781f497fa033c92333d10");
        ak_mpzn_set_hexstr(y_mont_correct, ak_mpzn128_size, "a6672afbafbec982c91125d54b51666f");
        ak_128_to_montgomery(x_mont_got, x, &ctx);
        ak_128_to_montgomery(y_mont_got, y, &ctx);

        REQUIRE(ak_128_equal(x_mont_got, x_mont_correct));
        REQUIRE(ak_128_equal(y_mont_got, y_mont_correct));

        SECTION("Multiplication")
        {
            ak_mpzn128 mul_got, mul_expected;
            ak_mpzn_set_hexstr(mul_expected, ak_mpzn128_size, "5c57cc932c9bd51b683b418f79048723");
            ak_128_montgomery_mul(mul_got, x_mont_got, y_mont_got, &ctx);
            REQUIRE(ak_128_equal(mul_got, mul_expected));

            ak_mpzn128 mul_common_got;
            ak_mpzn_mul_montgomery(mul_common_got, x_mont_got, y_mont_got, ctx.p, ctx.v[0], ak_mpzn128_size);
            REQUIRE(ak_128_equal(mul_common_got, mul_expected));
        }
    }
}
