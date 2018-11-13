#include <stdio.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <time.h>
#define NOA 3 //For testing NOA is number of rows to add

void fulladder(LweSample* a, const LweSample* b,LweSample* carryin,LweSample* temp0,LweSample* temp1,LweSample* temp2,const TFheGateBootstrappingCloudKeySet* cloud_key)
{
    bootsXOR(temp0,a,b,cloud_key);//temp0 = a XOR b
    bootsAND(temp1,temp0,carryin,cloud_key);//temp1 = (a XOR b) AND cin
    bootsAND(temp2,a,b,cloud_key);//temp2 = a AND b
    bootsXOR(a,temp0,carryin,cloud_key);//sum = (a XOR b) XOR cin
    bootsOR(carryin,temp1,temp2,cloud_key);//cin = temp1 OR temp2
    return;
}

void addition(LweSample* encrypted_result,LweSample* operands[10001],const int total_bits,const TFheGateBootstrappingCloudKeySet* cloud_key)
{
    LweSample* carry = new_gate_bootstrapping_ciphertext_array(4, cloud_key->params);

    bootsCONSTANT(&carry[0],0,cloud_key);

    for(int i=0;i<32;i++)
    {
         bootsCONSTANT(&encrypted_result[i],0,cloud_key);
    }

    for(int i=0;i<NOA;i++)
    {
        for(int j=0;j<total_bits;j++)
        {
            fulladder(&encrypted_result[j],&operands[i][j],&carry[0],&carry[1],&carry[2],&carry[3],cloud_key);
        }
        bootsCONSTANT(&carry[0],0,cloud_key);
    }

    return;
}

int main()
{
    printf("Importing Cloud Key\n");
    FILE* cloud_file = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* cloud_key = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_file);
    fclose(cloud_file);

    const TFheGateBootstrappingParameterSet* params = cloud_key->params;

    printf("Importing Encrypted Data\n");
    LweSample* encrypted_total_charges[10001];
    FILE* cloud_data_file = fopen("cloud.data","rb");
    for(int i=0;i<10001;i++)
    {
        encrypted_total_charges[i] = new_gate_bootstrapping_ciphertext_array(32,params);
        for(int j=0;j<32;j++)
        {
            import_gate_bootstrapping_ciphertext_fromFile(cloud_data_file,&encrypted_total_charges[i][j],params);
        }

    }
    fclose(cloud_data_file);

    LweSample* encrypted_result = new_gate_bootstrapping_ciphertext_array(32,params);

    printf("Performing Homomorphic Computation...\n");

    struct timespec start,finish;
    double elapsed;

    clock_gettime(CLOCK_MONOTONIC,&start);
    addition(encrypted_result,encrypted_total_charges,32,cloud_key);
    clock_gettime(CLOCK_MONOTONIC,&finish);
    elapsed=(finish.tv_sec-start.tv_sec);
    elapsed+=(finish.tv_nsec-start.tv_nsec)/1000000000.0;

    printf("Time Taken to perform Homomorphic Encryption is %lf seconds\n",elapsed);

    printf("Exporting Encrypted Result\n");
    FILE* answer_data = fopen("answer.data","wb");
    for (int i=0; i<32; i++)
        export_gate_bootstrapping_ciphertext_toFile(answer_data, &encrypted_result[i], params);
    fclose(answer_data);

    printf("Cleaning Up\n");
    delete_gate_bootstrapping_ciphertext_array(32, encrypted_result);
    for(int i=0;i<10001;i++)
    {
        delete_gate_bootstrapping_ciphertext_array(32, encrypted_total_charges[i]);
    }
    delete_gate_bootstrapping_cloud_keyset(cloud_key);


    return 0;
}
