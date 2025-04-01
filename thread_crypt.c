//Avesta Mirashrafi
//11/21/2023
//CS333 Lab 3

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <string.h>
#include <crypt.h>
#include <pthread.h>
#include <time.h>

#include "thread_crypt.h"

#define MICROSECONDS_PER_SECOND 1000000.0
#define PASSWORD_MAX_LENGTH 256


typedef struct { //thread-local data
	char** passwords;
	int s;
	int f;
	int alg;
	int salt_length;
	FILE * out;
	long rounds;
	pthread_mutex_t mut;
} thread_data;

double elapse_time(struct timeval *, struct timeval *);
void * hasher(void* arg);
void salter(int alg, int salt_length, long rounds, char * salt); 

void salter(int alg, int salt_length, long rounds, char * salt){
	char partial[salt_length +1];
	int num_digits = snprintf(NULL, 0, "%ld", rounds);

	for(int i = 0; i < salt_length; ++i){  //generate "Random" salt to desired
		partial[i] = SALT_CHARS[rand() % (sizeof(SALT_CHARS) - 1)]; //length
	}

	partial[salt_length] = '\0';

	switch(alg){ //form the rest of the salt based on the algorithm and rounds
		case 0:
			strcpy(salt, partial);
			break;  
		case 1:
			snprintf(salt, salt_length + 4, "$1$%.*s$", salt_length, partial);
			break;
		case 5:
			snprintf(salt, salt_length + 13+ num_digits, "$5$rounds=%ld$%.*s$", rounds, salt_length, partial);
			break;
		case 6:
			snprintf(salt, salt_length + 13 + num_digits, "$6$rounds=%ld$%.*s$", rounds, salt_length, partial);
			break;
		default:
			perror("invalid algorithm\n");
	}
	salt[strlen(salt) +1] = '\0'; //null terminate the end of the salt string
}

int main(int argc, char *argv[]){
	int opt;  //So many variables
	char * input_file = NULL;
	char * output_file = NULL;
	FILE * input;
	FILE * output = stdout;

	int alg = 0;  //even more variables
	int salt_length = 0;
	long rounds = 5000;
	long seed = 0;
	int num_threads = 1;

	char read_line[1024];  //buffer for fgets
	char ** passwords;   //array of passwords
	int passwordLength = 0;  //number of passwords
	int i = 0;

	int split;
	thread_data Tdata[20]; //thread local objects that get passed into threads
	pthread_t threads[20]; //actual threads

	struct timeval start; //time variables for testing
	struct timeval fin;
	//double total_time;
	
	while((opt = getopt(argc, argv, OPTIONS)) != -1){
		switch(opt){
			case 'i':
				if((input_file = optarg) == NULL){ //error check for file
					perror("Input file NULL\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'o':
				output_file = optarg;
				output = fopen(output_file, "w");
				break;
			case 'a':
				alg = atoi(optarg);			
				break;
			case 'l':
				salt_length = atoi(optarg);
				break;
			case 'r':
				rounds = atoi(optarg);
				if(rounds < 1000){ //if rounds are out of bounds,
					rounds = 1000;  //adjust the # of rounds
				}
				if(rounds > 999999999){
					rounds = 999999999;
				}
				break;
			case 'R':
				seed = atol(optarg);
				srand(seed);
				break;
			case 't':
				num_threads = atoi(optarg);
				if(num_threads > 20){ //adjust threads to 20
					num_threads = 20; //if over 20
				}
				break;
			case 'v':
				printf("Verbose enabled\n");
				break;
			case 'h':
				printf("./thread_crypt ...\n");
				printf("	Options: i:o:hva:l:R:t:r\n");
				printf("	-i file         input file name (required)\n");
				printf("	-o file		output file name (default stdout)\n");
				printf("	-a # 		algorithm to use for hashing [0,1,5,6] (default 0 = DES)\n");
				printf("	-l # 		length of salt (default 2 for DES, 8 for MD-5, 16 for SHA)\n");
				printf("	-r #		rounds to use for SHA-256, or SHA-512 (default 5000)\n");
				printf("	-R #		seed for rand() (default none)\n");
				printf("	-t #		number of threads to create (default 1)\n");
				printf("	-v		enable verbose mode\n");
				printf("	-h		helpful text\n");
				break;
			default:
				exit(EXIT_FAILURE);
				break;
		}

	}
	
	if(input_file == NULL){  //error check for bad input
		perror("Input file NULL\n");
		exit(EXIT_FAILURE);
	}

	if(seed == 0) srand(time(NULL));  //seed to random if no seed is set

	switch (alg) {  //this switch statement adjusts salt length
		case 0:    //if out of bounds
			salt_length = 2;
			break;
		case 1:
			if(salt_length < 2 || salt_length > 8){
				salt_length = 8;
			}
			break;
		case 5:   //default to largest size if not set or out of bounds
			if(salt_length < 2 || salt_length > 16){
				salt_length = 16;
			}
			break;
		case 6:
			if(salt_length < 2 || salt_length > 16){
				salt_length = 16;
			}
			break;
		default:
			perror("invalid algorithm\n");
			exit(EXIT_FAILURE);
	}

	input = fopen(input_file, "r");

	while(fgets(read_line, sizeof(read_line), input)){
		++passwordLength; //calculate number of passwords
	}

	fseek(input, 0, SEEK_SET);  //reset to beginning of file
	passwords = malloc(passwordLength * sizeof(char*));

	while(fgets(read_line, sizeof(read_line), input)){ //this loop stores all
		size_t len = strlen(read_line);        //the passwords in a char **
		if(len > 0 && read_line[len - 1] == '\n'){
			read_line[len - 1] = '\0';
		}
		passwords[i] = strdup(read_line); //copy password into char ** array
		++i;
	}

	fclose(input);

	if(passwordLength < num_threads){  //if there are more threads than passwords
		num_threads = passwordLength; //we adjust the number of threads because extra
	}                                 //threads would be wasted

	split = passwordLength / num_threads; //splits up passwords to disperce to threads

	for(int j = 0; j < num_threads; ++j){
		int threadPasswordCount; 
		Tdata[j].s = j * split; //where to start in password list for thread
		Tdata[j].f = (j == num_threads - 1) ? passwordLength -1 : (j + 1) * split -1;   //where to end password list for thread
		threadPasswordCount = Tdata[j].f - Tdata[j].s + 1;

		Tdata[j].passwords = malloc(threadPasswordCount * sizeof(char*));

		for (int k = 0; k < threadPasswordCount; ++k) {  //asign passwords
			Tdata[j].passwords[k] = strdup(passwords[Tdata[j].s + k]);
		}

		Tdata[j].out = output;  //copy other data
		Tdata[j].alg = alg;
		Tdata[j].salt_length = salt_length;
		Tdata[j].rounds = rounds;

		if (pthread_mutex_init(&Tdata[j].mut, NULL) != 0) {  //create mutex
			perror("Mutex initialization failed");  //for thread local struct
			return EXIT_FAILURE;
		} 
	}

	gettimeofday(&start, NULL);

	if(output_file != NULL){ //assign output file if there is one
		output = fopen(output_file, "w");
		fclose(output);
	}

	for(int j = 0; j < num_threads; ++j){  //create threads
		if(pthread_create(&threads[j], NULL, hasher, &Tdata[j]) != 0){
			perror("thread create error");
			return EXIT_FAILURE;
		}
	}

	for(int j = 0; j < num_threads; ++j){  //join threads
		if(pthread_join(threads[j], NULL) != 0){
			perror("thread join error");
			return EXIT_FAILURE;
		}
	}

	for (int j = 0; j < num_threads; ++j) { //destroy threads
		pthread_mutex_destroy(&Tdata[j].mut);
	}

	gettimeofday(&fin, NULL);

	//total_time = elapse_time(&start, &fin);

	for(int j = 0; j < passwordLength; ++j){
		free(passwords[j]);
	}

	free(passwords);

	for (int j = 0; j < num_threads; ++j) { //loop that frees all thread memory
		for (int k = 0; k < Tdata[j].f - Tdata[j].s + 1; ++k) {
			free(Tdata[j].passwords[k]);
		}
		free(Tdata[j].passwords);
		pthread_mutex_destroy(&Tdata[j].mut);
	}

	//printf("total time: %8.2lf\n", total_time);
	//the print time is commented out, but it was used for testing
	return EXIT_SUCCESS;
}

//this was mainly for testing purposes
double elapse_time(struct timeval *t0, struct timeval *t1){  //function used
	double et = ((double) (t1->tv_usec - t0->tv_usec))   //for calculating time
		/ MICROSECONDS_PER_SECOND                        //spent in threads
		+ ((double) (t1->tv_sec - t0->tv_sec));
	return et;
}



void *hasher(void *data) {  //this function takes our passwords and salts
	thread_data *Tdata = (thread_data *)data;  //and uses crypt to create 
                                               //a hashed password

	for (int i = 0; i < Tdata->f - Tdata->s + 1; ++i) {
		struct crypt_data result; //struct for crypt_r
		char *hashPassword;
		char * salt = (char *)malloc((128) * sizeof(char)); 

		size_t hashPasswordLen = PASSWORD_MAX_LENGTH;
		char *hashed = (char *)malloc(hashPasswordLen);

		pthread_mutex_lock(&Tdata->mut);  //lock mutex
		salter(Tdata->alg, Tdata->salt_length, Tdata->rounds, salt); //call salt function
		result.initialized = 0;

		if (hashed == NULL) { //error check for a crypt error
			perror("Memory allocation error for hash password");
			pthread_mutex_unlock(&Tdata->mut);
			pthread_exit(NULL);
		}

		hashPassword = crypt_r(Tdata->passwords[i], salt, &result);

		if (hashPassword != NULL) {  //combine the old password and the new one into one string
			snprintf(hashed, hashPasswordLen, "%s:%s", Tdata->passwords[i], hashPassword);
			hashed[hashPasswordLen - 1] = '\0';

			fprintf(Tdata->out, "%s\n", hashed); //use fprintf to either print to file or stdout
		} else {
			perror("error invalid output file");
		}

		free(salt);
		free(hashed); //free allocated memory
		pthread_mutex_unlock(&Tdata->mut); //unlock mutex
	}

	pthread_exit(NULL);
}


