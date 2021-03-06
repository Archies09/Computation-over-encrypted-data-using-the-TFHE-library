#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>


int main()
{
    printf("Importing Secret Key\n");
    FILE* secret_file = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* secret_key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_file);
    fclose(secret_file);

    const TFheGateBootstrappingParameterSet* params = secret_key->params;

    LweSample* encrypted_result = new_gate_bootstrapping_ciphertext_array(32, params);

    printf("Importing Encrypted Answer\n");
    FILE* answer_data = fopen("answer.data","rb");
    for (int i=0; i<32; i++)
    {
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &encrypted_result[i], params);
    }
    fclose(answer_data);

    printf("Decrypting Answer\n");
    int32_t result = 0;
    for (int i=0; i<32; i++) {
        int ai = bootsSymDecrypt(&encrypted_result[i], secret_key)>0;
        result|=(ai<<i);
    }

    printf("Result is: %d\n",result);

    printf("Cleaning Up\n");
    delete_gate_bootstrapping_ciphertext_array(32, encrypted_result);
    delete_gate_bootstrapping_secret_keyset(secret_key);

}
