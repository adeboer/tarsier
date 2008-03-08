/* tarsier.c, adb, gpl2, -larchive -lssl  */

#include <stdio.h>
#include <archive.h>
#include <sys/stat.h>
#include <openssl/evp.h>

int main (int argc, char *argv[]) {
	struct archive *ark;
	struct archive_entry *entry;
	int rc;
	char buff[4096];
	mode_t ftype;
	EVP_MD_CTX mdctx;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, i;

	ark = archive_read_new();
	archive_read_support_compression_all(ark);
	archive_read_support_format_all(ark);

	rc = archive_read_open_FILE(ark, stdin);

	EVP_MD_CTX_init(&mdctx);

	while (archive_read_next_header(ark, &entry) == ARCHIVE_OK) {
		ftype = archive_entry_filetype(entry);
		if (S_ISREG(ftype)) {
			EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL);
			while (rc = archive_read_data(ark, buff, sizeof(buff))) {
				EVP_DigestUpdate(&mdctx, buff, rc);
				}
			EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
			for(i = 0; i < md_len; i++) printf("%02x", md_value[i]);
			printf("  %s\n",archive_entry_pathname(entry));
			}
		}
	archive_read_finish(ark);
	EVP_MD_CTX_cleanup(&mdctx);
	}
