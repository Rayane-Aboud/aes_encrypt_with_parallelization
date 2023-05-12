#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#define N 16
#define DIM 4
#define NB_ROUND 11
typedef struct block_128{
    uint8_t bytes[DIM][DIM];
}block_128;

typedef struct block_vector
{
    block_128* block_vec;
    long int n_blocks;
    long int string_len;
}block_vector;

static const uint8_t s_box[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t mix_matrix[N]={
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02};

static const uint8_t rcon[10]={
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36};

/*----------------everything about bloc structure----------------*/
void init_block_vector(block_vector* vec);
void gen_str_cnt_blocks(block_vector* vec,block_vector*counter_vec ,char* string);
void print_block_vec(block_vector* vec);
/*--------------------generating the counter blocs------------------------*/


/*---------------------------------------------------------------*/
void aes_ctr_encryption_128(block_128* counter_block,block_128* k_block,block_128* msg_block);


















int main(int argc,char* argv[]){
    block_vector str_vector;
    block_vector counter;
    init_block_vector(&str_vector);
    init_block_vector(&counter);
    block_128 key_block;
    key_block.bytes[0][0]=0x2b;key_block.bytes[0][1]=0x28;key_block.bytes[0][2]=0xab;key_block.bytes[0][3]=0x09;
    key_block.bytes[1][0]=0x7e;key_block.bytes[1][1]=0xae;key_block.bytes[1][2]=0xf7;key_block.bytes[1][3]=0xcf;
    key_block.bytes[2][0]=0x15;key_block.bytes[2][1]=0xd2;key_block.bytes[2][2]=0x15;key_block.bytes[2][3]=0x4f;
    key_block.bytes[3][0]=0x16;key_block.bytes[3][1]=0xa6;key_block.bytes[3][2]=0x88;key_block.bytes[3][3]=0x3c;


    FILE *fp;
  char *file_contents;
  long file_size;

  // Open the file for reading
  fp = fopen("file_to_encrypt.txt", "r");
  if (fp == NULL) {
    perror("Error opening file");
    return 1;
  }

  // Get the size of the file
  fseek(fp, 0, SEEK_END);
  file_size = ftell(fp);
  rewind(fp);

  // Allocate memory to store the file contents
  file_contents = (char *)malloc(file_size * sizeof(char));
  if (file_contents == NULL) {
    perror("Error allocating memory");
    fclose(fp);
    return 1;
  }

  // Read the file into the string
  size_t result = fread(file_contents, sizeof(char), file_size, fp);
  if (result != file_size) {
    perror("Error reading file");
    free(file_contents);
    fclose(fp);
    return 1;
  }

  // Add a null terminator to the end of the string
  file_contents[file_size] = '\0';

  // Close the file
  fclose(fp);




    gen_str_cnt_blocks(&str_vector,&counter,file_contents);
    print_block_vec(&str_vector);
    print_block_vec(&counter);
    
    double start_time,end_time;
    start_time = omp_get_wtime();
    #pragma omp parallel for
    for(int i=0;i<counter.n_blocks;i++){
        aes_ctr_encryption_128(&(counter.block_vec[i]),&key_block,&(str_vector.block_vec[i]));
    }
    end_time = omp_get_wtime();
    

    print_block_vec(&str_vector);
    print_block_vec(&counter);

    printf("Elapsed time: %f seconds\n", end_time - start_time);

    free(file_contents);
    free(str_vector.block_vec);
    free(counter.block_vec);
    
}



















void init_block_vector(block_vector* vec){
    vec->block_vec=NULL;
    vec->n_blocks=0;
    vec->string_len=0;
}

void gen_str_cnt_blocks(block_vector* vec,block_vector* counter_vec,char* string){
    int length=strlen(string);
    /*nb block of each one*/
    vec->n_blocks= (length/N)+((length%N==0)?0:1);
    counter_vec->n_blocks=vec->n_blocks;

    /*allocate space for both vectors*/
    vec->block_vec=malloc(vec->n_blocks*sizeof(block_vector));
    counter_vec->block_vec=malloc(counter_vec->n_blocks*sizeof(block_vector));
    
    /*length of the string for each*/
    vec->string_len=length;
    counter_vec->string_len=counter_vec->n_blocks*N;//useless info in this case

    //init string vector
    for(int i=0;i<length;i++){
        int idx_str_blk=i%N;
        (vec->block_vec[i/N]).bytes[idx_str_blk%DIM][idx_str_blk/DIM]=string[i];
    }

    //init counter vector
    //first half
    srand(time(NULL));
    /*initialiser la premiere partie*/
    for(int i=0;i<DIM;i++){
        for(int j=0;j<DIM/2;j++){
            int value=rand()%255;
            for(int b=0;b<counter_vec->n_blocks;b++){
                counter_vec->block_vec[b].bytes[i][j]=value;
            }
        }
    }
    /*initialiser la dexième partie*/
    
    for(long int b=0;b<counter_vec->n_blocks;b++){
        counter_vec->block_vec[b].bytes[3][3]=b%255;
        counter_vec->block_vec[b].bytes[2][3]=b/255%255;
        counter_vec->block_vec[b].bytes[1][3]=b/(255*255)%255;
        counter_vec->block_vec[b].bytes[0][3]=b/(255*255*255)%255;
        /*counter_vec->block_vec[b].bytes[3][2]=b/(255*255*255*255)%255;
        counter_vec->block_vec[b].bytes[2][2]=b/(255*255*255*255*255)%255;
        counter_vec->block_vec[b].bytes[1][2]=b/(255*255*255*255*255*255)%255;
        counter_vec->block_vec[b].bytes[0][2]=b/(255*255*255*255*255*255*255)%255;*/
    }
            
}

void print_block_vec(block_vector* vec){
    printf("------------------------------\n");
    printf("number of blocks:%ld\n",vec->n_blocks);
    printf("string length : %ld\n",vec->string_len);
    for(int i=0;i<vec->n_blocks;i++){
        printf("block %d :\n",i);
        printf("block length: %ld\n",(i!=vec->n_blocks-1)?N:vec->n_blocks%N);
        for(int j=0;j<N && i*N+j<vec->string_len;j++){
            printf("%x ",vec->block_vec[i].bytes[j%DIM][j/DIM]);
        }
        printf("\n");
    }
    printf("------------------------------\n");
    
}


void aes_ctr_encryption_128(block_128* counter_block,block_128* k_block,block_128* msg_block){


    uint8_t key_block[NB_ROUND][DIM][DIM];
    uint8_t w[DIM];
    //add the bloc key to the key table
    for (int i=0;i<DIM;i++){
        for (int j = 0; j < DIM; j++)
        {
            key_block[0][i][j]=k_block->bytes[i][j];
        }
        
    }

    /**/

    /*------------------------------------------------------------------------*/
    /*---------------------------Creation des round Key-------------------------*/
    /*------------------------------------------------------------------------*/
    for(int i=1;i<NB_ROUND;i++){//for each block
        //special case for first column
        //rot word
        uint8_t tmp=key_block[i-1][0][DIM-1];
        for(int l=0;l<DIM-1;l++){
            w[l]=key_block[i-1][l+1][DIM-1];
        }
        w[DIM-1]=tmp;
        //sub byte     
        for (int l = 0; l < DIM; l++){
            int tmp_i=w[l]/0x10;
            int tmp_j=w[l]%0x10;
            w[l] =s_box[tmp_i*16+tmp_j];
        }
        //xor 
        for(int l=0;l<DIM;l++){
            key_block[i][l][0]=key_block[i-1][l][0]^w[l];
        }
        key_block[i][0][0]=key_block[i][0][0]^rcon[i-1];
        for(int j=1;j<DIM;j++){//for each other column
           for(int l=0;l<DIM;l++){
                key_block[i][l][j]=key_block[i][l][j-1]^key_block[i-1][l][j];
           }
        }
    }

    

    
    /*------------------------------------------------------------------------*/


    /*------------------------------------------------------------------------*/
    /*----------------------Before going to the loop---------------------------*/
    /*------------------------------------------------------------------------*/

    


    // encrypt the round 0
    for(int i=0;i<DIM;i++){
        for(int j=0;j<DIM;j++){
            counter_block->bytes[i][j]=counter_block->bytes[i][j]^key_block[0][i][j];
        }
    }

    /*------------------------------------------------------------------------*/
    /*----------------------Loop---------------------------*/
    /*------------------------------------------------------------------------*/
    
    for(int r=1;r<NB_ROUND-1;r++){
        //bite substitution
        for (int i=0;i<DIM;i++){
            for (int j = 0; j < DIM; j++){
                int tmp_i=counter_block->bytes[i][j]/0x10;
                int tmp_j=counter_block->bytes[i][j]%0x10;
                counter_block->bytes[i][j] =s_box[tmp_i*16+tmp_j];
            }
        }

        //shift row
        for(int i=0;i<DIM;i++){
            for(int nb_shift=0;nb_shift<i;nb_shift++){
                int tmp=counter_block->bytes[i][0];
                for(int j=0;j<DIM-1;j++){
                    counter_block->bytes[i][j]=counter_block->bytes[i][j+1];
                }
                counter_block->bytes[i][DIM-1]=tmp;
            }
        }
        //Mix columns
        uint8_t tmp[N]={
            0,0,0,0,
            0,0,0,0,
            0,0,0,0,
            0,0,0,0};
        for(int i=0;i<DIM;i++){
            for(int j=0;j<DIM;j++){
                for(int k=0;k<DIM;k++){
                    tmp[i*DIM+j]=mix_matrix[i*DIM+k]*counter_block->bytes[k][j];
                }
            }
        }
        //save Matrix
        for(int i=0;i<DIM;i++){
            for(int j=0;j<DIM;j++){
                counter_block->bytes[i][j]=tmp[i*DIM+j];
            }
        }

        //addRoundKey
        for(int i=0;i<DIM;i++){
            for(int j=0;j<DIM;j++){
                counter_block->bytes[i][j]^=key_block[r][i][j];
            }
        }
    }


    /*------------------------------------------------------------------------*/
    /*----------------------after loop---------------------------------------------*/
    /*------------------------------------------------------------------------*/

    //subBytes
    for (int i=0;i<DIM;i++){
        for (int j = 0; j < DIM; j++){
            int tmp_i=counter_block->bytes[i][j]/0x10;
            int tmp_j=counter_block->bytes[i][j]%0x10;
            counter_block->bytes[i][j] =s_box[tmp_i*16+tmp_j];
        }
    }
    //shift row
    for(int i=0;i<DIM;i++){
        for(int nb_shift=0;nb_shift<i;nb_shift++){
            int tmp=counter_block->bytes[i][0];
            for(int j=0;j<DIM-1;j++){
                counter_block->bytes[i][j]=counter_block->bytes[i][j+1];
            }
            counter_block->bytes[i][DIM-1]=tmp;
        }
    }

    //addRoundKey
    for(int i=0;i<DIM;i++){
        for(int j=0;j<DIM;j++){
            counter_block->bytes[i][j]^=key_block[NB_ROUND-1][i][j];
        }
    }

    for(int i=0;i<DIM;i++){
        for(int j=0;j<DIM;j++){
            msg_block->bytes[i][j]^=counter_block->bytes[i][j];
        }
    }
    
}