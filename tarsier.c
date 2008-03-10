/* tarsier.c, adb, gpl2, -larchive -lssl  */

#include <stdio.h>
#include <archive.h>
#include <sys/stat.h>
#include <openssl/evp.h>

int main (int argc, char *argv[]) {
	struct archive *ark;
	struct archive_entry *entry;
	int ast, rc;
	char buff[4096];
	mode_t ftype;
	EVP_MD_CTX mdctx;
	const EVP_MD *mdtype;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, i;
	FILE *fin;

	if (argc == 1) {
		fin = stdin;
		}
	else if (argc == 2) {
		fin = fopen(argv[1], "r");
		if (fin == NULL) {
			perror(argv[1]);
			exit(1);
			}
		}
	else {
		fprintf(stderr, "Usage: tarsier %d\n", argc);
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

	EVP_MD_CTX_init(&mdctx);
	mdtype = EVP_md5();

	while ((ast = archive_read_next_header(ark, &entry)) == ARCHIVE_OK) {
		ftype = archive_entry_filetype(entry);
		if (S_ISREG(ftype)) {
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
			printf("  %s\n",archive_entry_pathname(entry));
			}
		}
	if (ast != ARCHIVE_EOF) {
		fprintf(stderr, "Error parsing archive: %s\n", archive_error_string(ark));
		exit(1);
		}
	archive_read_finish(ark);
	EVP_MD_CTX_cleanup(&mdctx);
	}
