#include <stdio.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <time.h>

void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* cloud_key)
{
    bootsXNOR(tmp,a,b,cloud_key);
    bootsMUX(result,tmp,lsb_carry,a,cloud_key);
}


void row_counter(LweSample* encrypted_count[10001],LweSample* operands[10001],LweSample* encrypted_threshold,const int total_bits,const TFheGateBootstrappingCloudKeySet* cloud_key)
{
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, cloud_key->params);
    LweSample* zerobit = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);
    LweSample* onebit = new_gate_bootstrapping_ciphertext_array(1, cloud_key->params);
    bootsCONSTANT(zerobit,0,cloud_key);
    bootsCONSTANT(onebit,1,cloud_key);

    for(int i=9801;i<10001;i++)
    {
        bootsCONSTANT(&tmps[0],0,cloud_key);
        for(int j=0;j<total_bits;j++)
        {
            compare_bit(&tmps[0],&operands[i][j],&encrypted_threshold[j],&tmps[0],&tmps[1],cloud_key);
        }
        bootsMUX(encrypted_count[i],&tmps[0],onebit,zerobit,cloud_key);
    }

    delete_gate_bootstrapping_ciphertext_array(2,tmps);
}


int main()
{
    FILE* cloud_file = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* cloud_key = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_file);
    fclose(cloud_file);

    const TFheGateBootstrappingParameterSet* params = cloud_key->params;

    LweSample* encrypted_total_cost[10001];
    LweSample* encrypted_count[10001];
    FILE* cloud_data_file = fopen("cloud.data","rb");
    for(int i=0;i<10001;i++)
    {
        encrypted_total_cost[i] = new_gate_bootstrapping_ciphertext_array(32,params);
        encrypted_count[i] = new_gate_bootstrapping_ciphertext_array(1,params);

        for(int j=0;j<32;j++)
        {
            import_gate_bootstrapping_ciphertext_fromFile(cloud_data_file,&encrypted_total_cost[i][j],params);
        }
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data_file,encrypted_count[i],params);
    }


    LweSample* encrypted_threshold = new_gate_bootstrapping_ciphertext_array(32,params);
    for(int j=0;j<32;j++)
    {
        import_gate_bootstrapping_ciphertext_fromFile(cloud_data_file,&encrypted_threshold[j],params);

    }


    fclose(cloud_data_file);

    printf("doing the homomorphic comparison...\n");

    struct timespec start, finish;
    double elapsed;

    clock_gettime(CLOCK_MONOTONIC,&start);
    row_counter(encrypted_count,encrypted_total_cost,encrypted_threshold,32,cloud_key);
    clock_gettime(CLOCK_MONOTONIC,&finish);
    elapsed=(finish.tv_sec-start.tv_sec);
    elapsed+=(finish.tv_nsec-start.tv_nsec)/1000000000.0;

    printf("Time Taken to perform Homomorphic Encryption is %lf seconds\n",elapsed);

    FILE* answer_data = fopen("answer.data","wb");
    for (int i=0; i<10001; i++)
    {
        export_gate_bootstrapping_ciphertext_toFile(answer_data, encrypted_count[i], params);
    }
    fclose(answer_data);


    for(int i=0;i<10001;i++)
    {
        delete_gate_bootstrapping_ciphertext_array(1, encrypted_count[i]);
    }
    delete_gate_bootstrapping_cloud_keyset(cloud_key);


    return 0;
}
