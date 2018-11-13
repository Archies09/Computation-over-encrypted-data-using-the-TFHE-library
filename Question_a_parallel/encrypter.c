#include <stdio.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>

int main()
{
    const int minimum_lambda = 110;//just a check for bits for security
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    printf("Generating Secret Keys\n");
    uint32_t seed[5];
    int prime = 17791;
    seed[0]=(uint32_t)time(NULL)%prime;
    seed[1]=seed[0]*(uint32_t)time(NULL)%prime;
    seed[2]=seed[1]*(uint32_t)time(NULL)%prime;
    seed[3]=seed[2]*(uint32_t)time(NULL)%prime;
    seed[4]=seed[3]*(uint32_t)time(NULL)%prime;

    tfhe_random_generator_setSeed(seed,5);

    TFheGateBootstrappingSecretKeySet* secret_key = new_random_gate_bootstrapping_secret_keyset(params);

    printf("Reading CSV File\n");
    int32_t len_of_stay[10001];
    int32_t ccs_code[10001];
    char ccs_desc[100];
    char title[200];
    int32_t ccs_pro_code[10001];
    int32_t total_charges[10001];
    int32_t total_costs[10001];

    FILE* test_data = fopen("TestData.csv","r");
    fscanf(test_data,"%[^\n]",title);
    int row_number = 0;
    while(fscanf(test_data,"%" SCNd32 "," "%" SCNd32 ",%[^,]," "%" SCNd32 "," "%" SCNd32 "," "%" SCNd32 ,&len_of_stay[row_number],&ccs_code[row_number],ccs_desc,&ccs_pro_code[row_number],&total_charges[row_number],&total_costs[row_number])!=EOF)
    {
        row_number++;
    }

    printf("Encrypting Total Charges column\n");
    LweSample* encrypted_total_charges[10001];
    for(int i=0;i<10001;i++)
    {
        encrypted_total_charges[i] = new_gate_bootstrapping_ciphertext_array(32,params);
        for(int j=0;j<32;j++)
        {
            bootsSymEncrypt(&encrypted_total_charges[i][j],(total_charges[i]>>j)&1,secret_key);
        }

    }

    printf("Exporting Secret Key\n");
    FILE* secret_file = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_file,secret_key);
    fclose(secret_file);

    printf("Exporting Cloud Key\n");
    FILE* cloud_file = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_file,&secret_key->cloud);
    fclose(cloud_file);

    printf("Exporting Encrypted Data for Cloud\n");
    FILE* cloud_data_file = fopen("cloud.data","wb");
    for(int i=0;i<10001;i++)
    {
        for(int j=0;j<32;j++)
        {
            export_gate_bootstrapping_ciphertext_toFile(cloud_data_file,&encrypted_total_charges[i][j],params);
        }
    }
    fclose(cloud_data_file);

    printf("Cleaning up\n");
    for(int i=0;i<10001;i++)
    {
        delete_gate_bootstrapping_ciphertext_array(32,encrypted_total_charges[i]);
    }
    delete_gate_bootstrapping_secret_keyset(secret_key);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}
