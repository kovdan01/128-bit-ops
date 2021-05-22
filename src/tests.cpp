#include <libakrypt.h>

#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>

#include <iostream>
#include <fstream>

class TestDataSingletone
{
public:
    static TestDataSingletone& get_instance()
    {
        static TestDataSingletone instance;
        return instance;
    }

    TestDataSingletone(const TestDataSingletone&) = delete;
    TestDataSingletone& operator=(const TestDataSingletone&) = delete;
    TestDataSingletone(TestDataSingletone&&) = delete;
    TestDataSingletone& operator=(TestDataSingletone&&) = delete;

    const nlohmann::json& data() const
    {
        return m_data;
    }

private:
    nlohmann::json m_data;

    TestDataSingletone()
    {
        std::ifstream input("data.json");
        std::string content{ std::istreambuf_iterator<char>(input),
                             std::istreambuf_iterator<char>() };
        m_data = nlohmann::json::parse(content);
    }
};

TEST_CASE("128-bit test", "128")
{
    const nlohmann::json& test_data = TestDataSingletone::get_instance().data();
    std::cerr << "Start!" << std::endl;
    for (const auto& elem : test_data)
    {
        ak_mpzn128 p, x, y;
        ak_mpzn_set_hexstr(p, ak_mpzn128_size, elem["p"].get<std::string>().c_str());
        ak_mpzn_set_hexstr(x, ak_mpzn128_size, elem["x"].get<std::string>().c_str());
        ak_mpzn_set_hexstr(y, ak_mpzn128_size, elem["y"].get<std::string>().c_str());

        // Arithmetic sum
        {
            ak_mpzn128 sum_got, sum_expected;
            ak_mpzn_set_hexstr(sum_expected, ak_mpzn128_size, elem["sum_arithmetic"].get<std::string>().c_str());
            ak_uint64 sign = ak_128_add(sum_got, x, y);
            REQUIRE(sign == elem["sum_arithmetic_sign"].get<ak_uint64>());
            REQUIRE(ak_128_equal(sum_got, sum_expected));
        }

        // Sum modulo P
        {
            ak_mpzn128 sum_got, sum_expected;
            ak_mpzn_set_hexstr(sum_expected, ak_mpzn128_size, elem["sum_modulo"].get<std::string>().c_str());
            ak_128_add_mod(sum_got, x, y, p);
            REQUIRE(ak_128_equal(sum_got, sum_expected));
        }

        // Arithmetic subtraction
        {
            ak_mpzn128 sub_got, sub_expected;
            ak_mpzn_set_hexstr(sub_expected, ak_mpzn128_size, elem["sub_arithmetic"].get<std::string>().c_str());
            ak_uint64 sign = ak_128_sub(sub_got, x, y);
            REQUIRE(sign == elem["sub_arithmetic_sign"].get<ak_uint64>());
            REQUIRE(ak_128_equal(sub_got, sub_expected));
        }

        // Subtraction modulo P
        {
            ak_mpzn128 sub_got, sub_expected;
            ak_mpzn_set_hexstr(sub_expected, ak_mpzn128_size, elem["sub_modulo"].get<std::string>().c_str());
            ak_128_sub_mod(sub_got, x, y, p);
            REQUIRE(ak_128_equal(sub_got, sub_expected));
        }

        // Arithmetic multiplication
        {
            ak_mpzn256 mul_got, mul_expected;
            ak_mpzn_set_hexstr(mul_expected, ak_mpzn256_size, elem["mul_arithmetic"].get<std::string>().c_str());
            ak_128_mul(mul_got, x, y);
            REQUIRE(ak_mpzn_cmp(mul_got, mul_expected, ak_mpzn256_size) == 0);
        }

        // Multiplication modulo P
        {
            ak_mpzn128 mul_got, mul_expected;
            ak_mpzn_set_hexstr(mul_expected, ak_mpzn128_size, elem["mul_modulo"].get<std::string>().c_str());
            ak_128_mul_mod(mul_got, x, y, p);
            REQUIRE(ak_128_equal(mul_got, mul_expected));
        }

        // Division modulo P
        {
            ak_mpzn256 z;
            ak_mpzn_set_hexstr(z, ak_mpzn256_size, elem["z"].get<std::string>().c_str());
            ak_mpzn128 quot_got, quot_expected, mod_got, mod_expected;
            ak_mpzn_set_hexstr(quot_expected, ak_mpzn128_size, elem["quot_modulo"].get<std::string>().c_str());
            ak_mpzn_set_hexstr(mod_expected,  ak_mpzn128_size, elem["mod_modulo"].get<std::string>().c_str());
            ak_uint64 sign = ak_128_div(quot_got, mod_got, z, p);
            REQUIRE(ak_128_equal(quot_got, quot_expected));
            REQUIRE(sign == elem["quot_modulo_sign"].get<ak_uint64>());
            REQUIRE(ak_128_equal(mod_got,  mod_expected));
        }

        // Inverse modulo P
        {
            ak_mpzn128 inverse_got, inverse_expected;
            ak_mpzn_set_hexstr(inverse_expected, ak_mpzn128_size, elem["inverse_modulo"].get<std::string>().c_str());
            ak_128_inverse(inverse_got, x, p);
            REQUIRE(ak_128_equal(inverse_got,  inverse_expected));
        }

        // Montgomery
        {
            ak_mpzn128 v_expected, r_expected, r2_expected;
            ak_mpzn_set_hexstr(v_expected, ak_mpzn128_size, elem["v"].get<std::string>().c_str());
            ak_mpzn_set_hexstr(r_expected, ak_mpzn128_size, elem["r"].get<std::string>().c_str());
            ak_mpzn_set_hexstr(r2_expected, ak_mpzn128_size, elem["r2"].get<std::string>().c_str());

            ak_montgomery_context_128 ctx;
            ak_mpzn_set(ctx.p, p, ak_mpzn128_size);
            ak_128_montgomery_init(&ctx);

            REQUIRE(ak_128_equal(ctx.v, v_expected));
            REQUIRE(ak_128_equal(ctx.r, r_expected));
            REQUIRE(ak_128_equal(ctx.r2, r2_expected));

            ak_mpzn128 x_mont_got, x_mont_correct, y_mont_got, y_mont_correct;
            ak_mpzn_set_hexstr(x_mont_correct, ak_mpzn128_size, elem["x_montgomery"].get<std::string>().c_str());
            ak_mpzn_set_hexstr(y_mont_correct, ak_mpzn128_size, elem["y_montgomery"].get<std::string>().c_str());
            ak_128_to_montgomery(x_mont_got, x, &ctx);
            ak_128_to_montgomery(y_mont_got, y, &ctx);

            REQUIRE(ak_128_equal(x_mont_got, x_mont_correct));
            REQUIRE(ak_128_equal(y_mont_got, y_mont_correct));

            // Multiplication
            {
                ak_mpzn128 mul_got, mul_expected;
                ak_mpzn_set_hexstr(mul_expected, ak_mpzn128_size, elem["mul_montgomery"].get<std::string>().c_str());
                ak_128_montgomery_mul(mul_got, x_mont_got, y_mont_got, &ctx);
                REQUIRE(ak_128_equal(mul_got, mul_expected));

                ak_mpzn128 mul_common_got;
                ak_mpzn_mul_montgomery(mul_common_got, x_mont_got, y_mont_got, ctx.p, ctx.v[0], ak_mpzn128_size);
                REQUIRE(ak_128_equal(mul_common_got, mul_expected));
            }
        }
    }
}
