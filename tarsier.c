/* tarsier.c, adb, gpl2, -larchive -lssl  */

#include <stdio.h>
#include <archive.h>
#include <archive_entry.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <time.h>

int main (int argc, char *argv[]) {
	struct archive *ark;
	struct archive_entry *entry;
	int ast, rc;
	char buff[4096];
	mode_t ftype;
	EVP_MD_CTX mdctx;
	const EVP_MD *mdtype = EVP_md5();
	unsigned char md_value[EVP_MAX_MD_SIZE];
	char *dateformat = NULL;
	int md_len, i;
	int inopt = 1;
	int noneyet = 1;
	FILE *fin;
	time_t oldest;
	time_t newest;

	while (inopt) {
		switch(getopt(argc, argv, "msdD:")) {
		case -1:
			inopt = 0;
			break;
		case 'm':
			/* mdtype = EVP_md5(); */
			break;
		case 's':
			mdtype = EVP_sha1();
			break;
		case 'd':
			dateformat = "%c";
			mdtype = NULL;
			break;
		case 'D':
			dateformat = optarg;
			mdtype = NULL;
			break;
		}
	}

	if (argc == optind) {
		fin = stdin;
		}
	else if (argc == optind + 1) {
		fin = fopen(argv[optind], "r");
		if (fin == NULL) {
			perror(argv[optind]);
			exit(1);
			}
		}
	else {
		fprintf(stderr, "Usage: tarsier [-m|-s|-d|-D fmt] %d\n", argc);
		exit (2);
		}

	ark = archive_read_new();
	if (ark == NULL) {
		fprintf(stderr, "archive_read_new() failed\n");
		exit(1);
		}
	archive_read_support_compression_all(ark);
	archive_read_support_format_all(ark);
	if (archive_read_open_FILE(ark, fin)) {
		fprintf(stderr, "Error opening archive: %s\n", archive_error_string(ark));
		exit(1);
		}

	if (mdtype) EVP_MD_CTX_init(&mdctx);

	while ((ast = archive_read_next_header(ark, &entry)) == ARCHIVE_OK) {
		ftype = archive_entry_filetype(entry);
		time_t fage = archive_entry_mtime(entry);
		if (noneyet || fage < oldest) oldest = fage;
		if (noneyet || fage > newest) newest = fage;
		noneyet = 0;
		char *space = "";
		if (S_ISREG(ftype)) {
			if (mdtype) {
			if (EVP_DigestInit_ex(&mdctx, mdtype, NULL) == 0) {
				fprintf(stderr, "EVP_DigestInit_ex failed\n");
				exit(1);
				}
			while (rc = archive_read_data(ark, buff, sizeof(buff))) {
				if (EVP_DigestUpdate(&mdctx, buff, rc) == 0) {
					fprintf(stderr, "EVP_DigestUpdate failed\n");
					exit(1);
					}
				}
			if (rc < 0) {
				int iswarn = (rc == ARCHIVE_WARN);
				fprintf(stderr, "%s reading archive: %s\n", (iswarn ? "Warning" : "Error"), archive_error_string(ark));
				if (!iswarn) {
					exit(1);
					}
				}
			if (EVP_DigestFinal_ex(&mdctx, md_value, &md_len) == 0) {
				fprintf(stderr, "EVP_DigestFinal_ex failed\n");
				exit(1);
				}
			for(i = 0; i < md_len; i++) printf("%02x", md_value[i]);
			space = "  ";
			} else {
				archive_read_data_skip(ark);
			}
			}
			if (*space) printf("%s%s\n", space, archive_entry_pathname(entry));
		}
	if (ast != ARCHIVE_EOF) {
		fprintf(stderr, "Error parsing archive: %s\n", archive_error_string(ark));
		exit(1);
		}
	archive_read_finish(ark);
	if (mdtype) EVP_MD_CTX_cleanup(&mdctx);
	if (dateformat != NULL && !noneyet) {
		struct tm * tmp = localtime(&newest);
		char out[256];
		if (strftime(out, sizeof(out), dateformat, tmp) == 0) {
			fprintf(stderr, "date format conversion failure");
			exit(1);
		}
		printf("%s\n", out);
	}
}
