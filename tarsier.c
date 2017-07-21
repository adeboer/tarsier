/* tarsier.c, adb, gpl2, -larchive -lssl */

#include <stdio.h>
#include <archive.h>
#include <archive_entry.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>

int main(int argc, char *argv[])
{
	struct archive *ark;
	struct archive_entry *entry;
	int ast, rc;
	char buff[4096];
	mode_t ftype;
	EVP_MD_CTX mdctx;
	const EVP_MD *mdtype = EVP_md5();
	unsigned char md_value[EVP_MAX_MD_SIZE];
	char *dateformat = NULL;
	char *gitbranch = NULL;
	int md_len, i;
	int inopt = 1;
	int noneyet = 1;
	int mct = 0;
	FILE *fin;
	time_t oldest;
	time_t newest;
	int64_t now = time(NULL);
	int pstrip = 0;

	while (inopt) {
		switch (getopt(argc, argv, "+msH:dD:g:p:")) {
		case -1:
			inopt = 0;
			break;
		case 'm':
			/* mdtype = EVP_md5(); */
			mct++;
			break;
		case 's':
			mdtype = EVP_sha1();
			mct++;
			break;
		case 'H':
			OpenSSL_add_all_digests();
			mdtype = EVP_get_digestbyname(optarg);
			if (mdtype == NULL) {
				fprintf(stderr, "Unrecognized hash function name\n");
				exit(2);
			}
			mct++;
			break;
		case 'd':
			dateformat = "%c";
			mdtype = NULL;
			mct++;
			break;
		case 'D':
			dateformat = optarg;
			mdtype = NULL;
			mct++;
			break;
		case 'g':
			mdtype = NULL;
			gitbranch = optarg;
			mct++;
			break;
		case 'p':
			pstrip = atoi(optarg);
			break;
		}
	}
	if (mct > 1) {
		fprintf(stderr, "Only one mode may be selected at a time.\n");
		exit(2);
	}

	if (argc == optind) {
		fin = stdin;
	} else if (argc == optind + 1) {
		fin = fopen(argv[optind], "r");
		if (fin == NULL) {
			perror(argv[optind]);
			exit(1);
		}
	} else {
		fprintf(stderr, "Usage: tarsier [-m|-s|-d|-D fmt] %d\n", argc);
		exit(2);
	}

	ark = archive_read_new();
	if (ark == NULL) {
		fprintf(stderr, "archive_read_new() failed\n");
		exit(1);
	}
	archive_read_support_filter_all(ark);
	archive_read_support_format_all(ark);
	if (archive_read_open_FILE(ark, fin)) {
		fprintf(stderr, "Error opening archive: %s\n",
				archive_error_string(ark));
		exit(1);
	}

	if (mdtype) {
		EVP_MD_CTX_init(&mdctx);
	}

	if (gitbranch) {
		printf("feature done\n");
		printf("commit refs/heads/%s\n", gitbranch);
		printf("committer Tester <test@example.org> %" PRId64 " +0000\n", now);
		printf("data <<EOD\nArchive Import\nEOD\ndeleteall\n");
	}

	while ((ast = archive_read_next_header(ark, &entry)) == ARCHIVE_OK) {
		ftype = archive_entry_filetype(entry);
		time_t fage = archive_entry_mtime(entry);
		int64_t size = archive_entry_size(entry);
		char const * path = archive_entry_pathname(entry);
		int i;
		for (i = pstrip; i > 0; i--) {
			char *p = strchr(path, '/');
			if (p) {
				path = p + 1;
			}
		}
		if (noneyet || fage < oldest) {
			oldest = fage;
		}
		if (noneyet || fage > newest) {
			newest = fage;
		}
		noneyet = 0;
		char *space = "";
		if (S_ISREG(ftype)) {
			if (mdtype) {
				if (EVP_DigestInit_ex(&mdctx, mdtype, NULL) == 0) {
					fprintf(stderr, "EVP_DigestInit_ex failed\n");
					exit(1);
				}
				while ((rc = archive_read_data(ark, buff, sizeof(buff)))>0) {
					if (EVP_DigestUpdate(&mdctx, buff, rc) == 0) {
						fprintf(stderr, "EVP_DigestUpdate failed\n");
						exit(1);
					}
				}
				if (EVP_DigestFinal_ex(&mdctx, md_value, &md_len) == 0) {
					fprintf(stderr, "EVP_DigestFinal_ex failed\n");
					exit(1);
				}
				for (i = 0; i < md_len; i++) {
					printf("%02x", md_value[i]);
				}
				space = "  ";
			} else if (gitbranch) {
				int gitperm = (archive_entry_perm(entry) & 0100) ? 0755 : 0644;
				printf("M %o inline %s\ndata %" PRId64 "\n", gitperm, path, size);
				while ((rc = archive_read_data(ark, buff, sizeof(buff)))>0) {
					fwrite(buff, rc, 1, stdout);
				}
				putchar('\n');
			} else {
				archive_read_data_skip(ark);
				rc = 0;
			}
			if (rc < 0) {
				int iswarn = (rc == ARCHIVE_WARN);
				fprintf(stderr, "%s reading archive: %s\n",
						(iswarn ? "Warning" : "Error"),
						archive_error_string(ark));
				if (!iswarn) {
					exit(1);
				}
			}
		} else if (S_ISLNK(ftype) && gitbranch) {
			printf("M 120000 inline %s\n", path);
			const char *sym = archive_entry_symlink(entry);
			int len = strlen(sym);
			printf("data %d\n", len);
			fwrite(sym, len, 1, stdout);
			putchar('\n');
		}
		if (*space) {
			printf("%s%s\n", space, path);
		}
	}
	if (ast != ARCHIVE_EOF) {
		fprintf(stderr, "Error parsing archive: %s\n",
				archive_error_string(ark));
		exit(1);
	}
	archive_read_free(ark);
	if (mdtype) {
		EVP_MD_CTX_cleanup(&mdctx);
	}
	if (dateformat != NULL && !noneyet) {
		struct tm *tmp = localtime(&newest);
		char out[256];
		if (strftime(out, sizeof(out), dateformat, tmp) == 0) {
			fprintf(stderr, "date format conversion failure");
			exit(1);
		}
		printf("%s\n", out);
	}
	if (gitbranch) {
		printf("\ndone\n");
	}
	return 0;
}
