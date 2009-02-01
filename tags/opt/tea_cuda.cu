/*
#
#    Copyright 2009, Lukas Lueg, knabberknusperhaus@yahoo.de
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <cuda/cuda.h>
#include <cuda_runtime.h>

/* Execution parameters */
#define THREADS_PER_THREADBLOCK 128
#define BLOCKBUFFER_SIZE (32768 * THREADS_PER_THREADBLOCK)
#define DATASIZE (128*1024*1024 / 16)
#define ITERCOUNT 10

/* Data structures */
typedef struct {
    uint32_t k0, k1, k2,k3;
} TEA_KEY;

typedef struct __align__(16) {
    uint32_t x_v0, x_v1, y_v0, y_v1;
} TEA_BLOCK;

/* Test-vectors for TEA with 32 rounds */
#define TV_KEY0 0x4E8E7829;
#define TV_KEY1 0xC88BA95E;
#define TV_KEY2 0xB84E28AF;
#define TV_KEY3 0xA0A47295;
#define TV_PLAIN0 0x8FADF3B3;
#define TV_PLAIN1 0x41EA3A0A
#define TV_CRYPT0 0xED650698
#define TV_CRYPT1 0xCF9F2B79

#define TEA_ROUND(block,key,sum) \
{ \
    (block).x_v0 += (((block).x_v1<<4) + (key).k0) ^ ((block).x_v1 + sum) ^ (((block).x_v1>>5) + (key).k1); \
    (block).x_v1 += (((block).x_v0<<4) + (key).k2) ^ ((block).x_v0 + sum) ^ (((block).x_v0>>5) + (key).k3); \
    (block).y_v0 += (((block).y_v1<<4) + (key).k0) ^ ((block).y_v1 + sum) ^ (((block).y_v1>>5) + (key).k1); \
    (block).y_v1 += (((block).y_v0<<4) + (key).k2) ^ ((block).y_v0 + sum) ^ (((block).y_v0>>5) + (key).k3); \
}

#define TEA_DELTA 0x9E3779B9



/* ### Device code below ### */

__global__
void cuda_encrypt (TEA_BLOCK *v, TEA_KEY key)
{
    TEA_BLOCK tmp_v;
    int idx = (blockIdx.x * blockDim.x + threadIdx.x);
    
    tmp_v = v[idx];
    TEA_ROUND(tmp_v, key, TEA_DELTA*1); TEA_ROUND(tmp_v, key, TEA_DELTA*2);
    TEA_ROUND(tmp_v, key, TEA_DELTA*3); TEA_ROUND(tmp_v, key, TEA_DELTA*4);
    TEA_ROUND(tmp_v, key, TEA_DELTA*5); TEA_ROUND(tmp_v, key, TEA_DELTA*6);
    TEA_ROUND(tmp_v, key, TEA_DELTA*7); TEA_ROUND(tmp_v, key, TEA_DELTA*8);
    TEA_ROUND(tmp_v, key, TEA_DELTA*9); TEA_ROUND(tmp_v, key, TEA_DELTA*10);
    TEA_ROUND(tmp_v, key, TEA_DELTA*11); TEA_ROUND(tmp_v, key, TEA_DELTA*12);
    TEA_ROUND(tmp_v, key, TEA_DELTA*13); TEA_ROUND(tmp_v, key, TEA_DELTA*14);
    TEA_ROUND(tmp_v, key, TEA_DELTA*15); TEA_ROUND(tmp_v, key, TEA_DELTA*16);
    TEA_ROUND(tmp_v, key, TEA_DELTA*17); TEA_ROUND(tmp_v, key, TEA_DELTA*18);
    TEA_ROUND(tmp_v, key, TEA_DELTA*19); TEA_ROUND(tmp_v, key, TEA_DELTA*20);
    TEA_ROUND(tmp_v, key, TEA_DELTA*21); TEA_ROUND(tmp_v, key, TEA_DELTA*22);
    TEA_ROUND(tmp_v, key, TEA_DELTA*23); TEA_ROUND(tmp_v, key, TEA_DELTA*24);
    TEA_ROUND(tmp_v, key, TEA_DELTA*25); TEA_ROUND(tmp_v, key, TEA_DELTA*26);
    TEA_ROUND(tmp_v, key, TEA_DELTA*27); TEA_ROUND(tmp_v, key, TEA_DELTA*28);
    TEA_ROUND(tmp_v, key, TEA_DELTA*29); TEA_ROUND(tmp_v, key, TEA_DELTA*30);
    TEA_ROUND(tmp_v, key, TEA_DELTA*31); TEA_ROUND(tmp_v, key, TEA_DELTA*32);
    v[idx] = tmp_v;
}


/* ### Host code below ### */


/* tea_encrypt() encrypts the data at 'inbuffer' using 'key' and writes results to 'outbuffer
   The length of inbuffer *must* be aligned to a 16-byte boundary */ 
int tea_encrypt(unsigned char* inbuffer, size_t len, unsigned char* outbuffer, TEA_KEY key)
{
    void* gpu_databuffer;
    cudaEvent_t evt;
    size_t transfer_size, numBufferBlocks, numThreadBlocks;
    cudaError_t ret;

    /* numBufferBlocks == number of TEA-double-blocks to encrypt */
    numBufferBlocks = len / sizeof(TEA_BLOCK);
    if (numBufferBlocks <= 0)
        return 0;


    /* We request page-locked memory from the CUDA api. Beware! */
    cudaMalloc(&gpu_databuffer, BLOCKBUFFER_SIZE * sizeof(TEA_BLOCK));
    while (numBufferBlocks > 0)
    {
        transfer_size = numBufferBlocks > BLOCKBUFFER_SIZE ? BLOCKBUFFER_SIZE : numBufferBlocks;
        cudaMemcpy(gpu_databuffer, inbuffer, transfer_size*sizeof(TEA_BLOCK), cudaMemcpyHostToDevice);

        cudaEventCreate(&evt);
        numThreadBlocks = transfer_size / THREADS_PER_THREADBLOCK;
        cuda_encrypt<<<numThreadBlocks, THREADS_PER_THREADBLOCK>>>((TEA_BLOCK *)gpu_databuffer, key);
        // usleeping() while the kernel is running saves CPU cycles but may decrease performance
        if (cudaEventRecord(evt, NULL) == cudaSuccess)
            while (cudaEventQuery(evt) == cudaErrorNotReady) { usleep(2000); }
        cudaEventDestroy(evt);
        
        ret = cudaGetLastError();
        if (ret != cudaSuccess || cudaThreadSynchronize() != cudaSuccess)
        {
            printf("Kernel failed to run. CUDA threw error message '%s'\n", cudaGetErrorString(ret));
            cudaFree(gpu_databuffer);
            return 0;
        }

        cudaMemcpy(outbuffer, gpu_databuffer, transfer_size * sizeof(TEA_BLOCK), cudaMemcpyDeviceToHost);
        
        inbuffer += transfer_size * sizeof(TEA_BLOCK);
        outbuffer += transfer_size * sizeof(TEA_BLOCK);
        numBufferBlocks -= transfer_size;
    }
    cudaFree(gpu_databuffer);
    
    return 1;
}

int main(int argc, char *argv[])
{
    cudaError_t ret;
    int i, j, cudadev, cudadevcount;
    TEA_KEY key;
    TEA_BLOCK* host_databuffer;
    struct cudaDeviceProp cuda_devprop;

    key.k0 = TV_KEY0;
    key.k1 = TV_KEY1;
    key.k2 = TV_KEY2;
    key.k3 = TV_KEY3;

    cudaGetDeviceCount(&cudadevcount);
    ret = cudaGetLastError();
    if (ret != cudaSuccess)
    {
        printf("CUDA failed to report devices with error '%s'\n", cudaGetErrorString(ret));
        return EXIT_FAILURE;
    }
    
    printf("Welcome to TEA-CUDA. We have %i device(s) available:\n", cudadevcount);
    for (cudadev = 0; cudadev < cudadevcount; cudadev++)
    {
        cudaGetDeviceProperties(&cuda_devprop, cudadev);
        printf("(%i) '%s'\n", cudadev, &cuda_devprop.name);
    }
    cudaGetDevice(&cudadev);
    if (ret != cudaSuccess)
    {
        printf("Failed to select device.\n");
        return EXIT_FAILURE;
    }
    printf("\nWorking on device '%s'...\n", &cuda_devprop.name);
    
    ret = cudaMallocHost((void**)(&host_databuffer), DATASIZE * sizeof(TEA_BLOCK));
    if (ret != cudaSuccess)
    {
        printf("Failed to allocate page-locked buffer.\n");
        return EXIT_FAILURE;
    }
    
    for (j = 0; j < ITERCOUNT; j++)
    {
	    printf("Run %i... ", j);
        for (i = 0; i < DATASIZE; i++)
        {
            host_databuffer[i].x_v0 = TV_PLAIN0;
            host_databuffer[i].x_v1 = TV_PLAIN1;
            host_databuffer[i].y_v0 = TV_PLAIN0;
            host_databuffer[i].y_v1 = TV_PLAIN1;
        }
        
        if (!tea_encrypt((unsigned char*)host_databuffer, DATASIZE*sizeof(TEA_BLOCK), (unsigned char*)host_databuffer, key))
        {
            printf("FAILED IN tea_encrypt()\n");
            break;
        }

        for (i = 0; i < DATASIZE; i++)
        {
            if (host_databuffer[i].x_v0 != TV_CRYPT0 || host_databuffer[i].x_v1 != TV_CRYPT1 || \
                host_databuffer[i].y_v0 != TV_CRYPT0 || host_databuffer[i].y_v1 != TV_CRYPT1)
            {
                printf("%i FAILED to correctly encrypt on GPU.\n", i);
                break;
            }
            
        }
        if (i != DATASIZE)
        {
            break;
        } else {
            printf("OK\n");
        }
    }
 
    cudaFreeHost(host_databuffer);

    return EXIT_SUCCESS;
}
