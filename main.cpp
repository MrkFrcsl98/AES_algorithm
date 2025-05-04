
#include "aes.hpp"      // include this for aes module
#include "aes-test.hpp" // and this for testing

int main(int argc, char **argv)
{
    try
    {

        AESTest::runGlobal();              // execute aes in all modes and all key sizes 

        // AESTest::run_AES_ECB_test();    // execute aes only in ECB mode and all key sizes(128, 192, 256)
        // AESTest::run_AES_CBC_test();    // execute aes only in CBC mode and all key sizes(128, 192, 256)
        // AESTest::run_AES_OFB_test();    // execute aes only in OFB mode and all key sizes(128, 192, 256)
        // AESTest::run_AES_CFB_test();    // execute aes only in CFB mode and all key sizes(128, 192, 256)
        // AESTest::run_AES_CTR_test();    // execute aes only in CTR mode and all key sizes(128, 192, 256)
        

        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
