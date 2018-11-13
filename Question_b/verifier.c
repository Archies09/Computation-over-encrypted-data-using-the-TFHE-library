#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <stdbool.h>


int main()
{
    printf("Importing Secret Key\n");
    FILE* secret_file = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* secret_key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_file);
    fclose(secret_file);

    const TFheGateBootstrappingParameterSet* params = secret_key->params;

    LweSample* answer[10001];

    FILE* answer_data = fopen("answer.data","rb");
    for (int i=0; i<10001; i++)
    {
        answer[i] = new_gate_bootstrapping_ciphertext_array(1, params);
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, answer[i], params);
    }
    fclose(answer_data);

    printf("Decrypting Answer\n");
    int32_t result=0;
    for (int i=0;i<10001;i++)
    {
        bool ai=bootsSymDecrypt(answer[i],secret_key);
        if(ai==1)
            result++;
    }

    printf("And the result is: %d rows\n",result);

    //clean up all pointers

    //delete_gate_bootstrapping_ciphertext_array(32, answer);
    delete_gate_bootstrapping_secret_keyset(secret_key);

}
