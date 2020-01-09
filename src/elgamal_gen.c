#include <ristretto_elgamal.h>
#include <omp.h>
#include <stdio.h>
#include <sys/stat.h>

/*
* This executable program samples two key pairs and generate the map (for the server).
*/

int main() {
	printf("\033[0;32m[INFO]\033[0m Generating two key pairs...\n");
	KeyGen(
			"./priv_1.key",
			"./priv_2.key",
			"./pub_1.key",
			"./pub_2.key",
			"./pub.key"
	);
	printf("\033[0;32m[INFO]\033[0m The first key pair is saved in ./priv_1.key and ./pub_1.key.\n");
	printf("\033[0;32m[INFO]\033[0m The second key pair is saved in ./priv_2.key and ./pub_2.key.\n");
	printf("\033[0;32m[INFO]\033[0m The merged public key is saved in ./pub.key.\n");

	/* check if /table exists */
	struct stat sb;
	if (stat("/table", &sb) == 0 && S_ISDIR(sb.st_mode)) {
		printf("\033[0;32m[INFO]\033[0m Found the /table directory.\n");
	} else {
		if (stat("/table", &sb) == 0) {
			printf("\033[0;32m[INFO]\033[0m Creating the /table directory.\n");

			mkdir("/table", S_IRWXU | S_IRWXG | S_IRWXO);
			/* this permission setting may not be the most appropriate */

			if (stat("/table", &sb) == 0) {
				printf("\033[0;32m[INFO]\033[0m Created the /table directory.\n");
			}
		} else {
			printf("\033[0;31m[ERROR]\033[0m Failed to create the /table directory.\n");
			exit(1);
		}
	}
	
	TablesMake("./pub_1.key", "./pub_2.key", "./pub.key", "/table/pub_1_%d.tab", "/table/pub_2_%d.tab", "/table/pub_%d.tab");
	
	return 0;
}
