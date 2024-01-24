#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct thread_data{
	int thread_id;
};

// Actual functions
void *thread_function(void *threadarg){
	int fd;
	char filename[30] = "/mnt/test/file_";
	char filenumber[3];
	struct thread_data *my_data;
	struct timespec start, end;
	long long unsigned int time;
	long long unsigned int time_sec;

	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	my_data = (struct thread_data*)threadarg;
	sprintf(filenumber,"%02d",my_data->thread_id);
	strcat(filename, filenumber);
	strcat(filename, ".txt");
	clock_gettime(CLOCK_REALTIME, &start);
	// Timer start
	fd = creat(filename,mode); 	
	// Timer end
	clock_gettime(CLOCK_REALTIME, &end);
	time_sec = end.tv_sec*1000000000 + end.tv_nsec;
	time = start.tv_sec*1000000000 + start.tv_nsec;;
	time = time_sec - time;
	printf("start: %lu\nend: %lu\n",start.tv_sec*1000000000+start.tv_nsec,end.tv_sec*1000000000+end.tv_nsec);
	close(fd);
	pthread_exit(NULL);
}

int main(int argc, char *argv[]){
	int i,n;
	pthread_t *thread_id;
	struct thread_data *td;
	if(argc != 2){
		printf("Usage: ./unit [Thread#] \n");
		return 0;
	}
	n= atoi(argv[1]);
	if(n==0){
		printf("Usage: [Thread#] should be a number\n");
		return 0;
	}
	thread_id = (pthread_t*)malloc(sizeof(pthread_t)*n);
	td = (struct thread_data*)malloc(sizeof(struct thread_data)*n);
	for(i=0;i<n;i++){
		td[i].thread_id=i;
		pthread_create(&thread_id[i],NULL, thread_function,&td[i]);
	}
	pthread_exit(NULL);
	return 0;
}
