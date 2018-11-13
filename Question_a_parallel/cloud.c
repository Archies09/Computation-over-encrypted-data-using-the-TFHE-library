#include <stdio.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <time.h>
#include <stdbool.h>
#include <omp.h>
#define NOA 3 //For testing NOA is number of rows to add


void full_adder(LweSample *encrypted_result,const LweSample *x,const LweSample *y,const int32_t nb_bits,const TFheGateBootstrappingCloudKeySet *cloud_key)
{
    const LweParams *in_out_params = cloud_key->params->in_out_params;

    LweSample *carry=new_LweSample_array(nb_bits+1,in_out_params);
    bootsCONSTANT(carry,0,cloud_key);

    LweSample *temp=new_LweSample_array(3,in_out_params);
    LweSample *generator=new_LweSample_array(nb_bits,in_out_params);
    LweSample *propagator=new_LweSample_array(nb_bits,in_out_params);

    #pragma omp parallel for schedule(runtime) num_threads(nb_bits)
    for (int32_t i=0;i<nb_bits;i++)
    {
        bootsAND(generator+i,x+i,y+i,cloud_key);
        bootsXOR(propagator+i,x+i,y+i,cloud_key);
    }


    #pragma omp parallel for schedule(runtime) num_threads(nb_bits)
    for (int32_t counter=1;counter<=nb_bits;counter++)
    {
        int g_count=counter-1;
        int p_count=counter-1;

        LweSample *res=new_LweSample_array(1,in_out_params);
        LweSample *intermed_p_value=new_LweSample_array(1,in_out_params);
        LweSample *intermed_g_value=new_LweSample_array(1,in_out_params);
        LweSample *intermed_total_value=new_LweSample_array(1,in_out_params);


        bootsCONSTANT(intermed_p_value,1,cloud_key);
        bootsCONSTANT(res,0,cloud_key);

        bootsCOPY(intermed_g_value,generator+g_count,cloud_key);
        bootsAND(intermed_total_value,intermed_p_value,intermed_g_value,cloud_key);
        g_count--;
        for(int i=counter;i>1;i--)
        {
            bootsOR(res,res,intermed_total_value,cloud_key);
            bootsCOPY(intermed_g_value,generator+g_count,cloud_key);
            g_count--;
            if(i==counter)
                bootsCOPY(intermed_p_value,propagator+p_count,cloud_key);
            else
                bootsAND(intermed_p_value,intermed_p_value,propagator+p_count,cloud_key);
            p_count--;
            bootsAND(intermed_total_value,intermed_p_value,intermed_g_value,cloud_key);
        }
        bootsOR(res,res,intermed_total_value,cloud_key);

        bootsCOPY(carry+counter,res,cloud_key);

    }

    #pragma omp parallel for schedule(runtime) num_threads(nb_bits)
    for (int32_t i=0; i<nb_bits;i++)
    {
       bootsXOR(encrypted_result+i,propagator+i,carry+i,cloud_key);
    }
}


void addition(LweSample* encrypted_result,LweSample* operands[10001],const int total_bits,const TFheGateBootstrappingCloudKeySet* cloud_key)
{
    for(int i=0;i<32;i++)
    {
         bootsCONSTANT(&encrypted_result[i],0,cloud_key);
    }
    for(int i=0;i<NOA;i++)
    {
        full_adder(encrypted_result,encrypted_result,operands[i],32,cloud_key);
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

    printf("Performing Homomorphic Computation in Parallel...\n");

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
