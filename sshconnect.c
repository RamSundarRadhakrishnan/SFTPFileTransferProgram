#include <stdio.h>
#include <stdlib.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    unsigned char *hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char *hexa;
    char *p;
    int cmp;
    int rc;
 
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA1,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */
 
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf(stderr, "Host key for server changed: it is now:\n");
            ssh_print_hexa("Public key hash", hash, hlen);
            fprintf(stderr, "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash(&hash);
 
            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");
 
            /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
 
        case SSH_KNOWN_HOSTS_UNKNOWN:
            hexa = ssh_get_hexa(hash, hlen);
            fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);
            ssh_string_free_char(hexa);
            ssh_clean_pubkey_hash(&hash);
            p = fgets(buf, sizeof(buf), stdin);
            if (p == NULL) {
                return -1;
            }
 
            cmp = strncasecmp(buf, "yes", 3);
            if (cmp != 0) {
                return -1;
            }
 
            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                fprintf(stderr, "Error %s\n", strerror(errno));
                return -1;
            }
 
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            ssh_clean_pubkey_hash(&hash);
            return -1;
    }
 
    ssh_clean_pubkey_hash(&hash);
    return 0;
}
int create_sftp_copy_session(ssh_session session){
	sftp_session sftp;
	int rc;
	sftp = sftp_new(session);
	if(sftp==NULL){
		fprintf(stderr, "Error establishing an SFTP session: %s\n", ssh_get_error(session));
		return SSH_ERROR;
	}
	rc = sftp_init(sftp);
	if(rc!=SSH_OK){
		fprintf(stderr, "Error initialising SFTP session: Code %d\n", sftp_get_error(sftp));
		sftp_free(sftp);
		return rc;
	}
	rc = sftp_mkdir(sftp, "upload",  S_IRWXU);
	if(rc!=SSH_OK){
		if(sftp_get_error(sftp) != SSH_FX_FILE_ALREADY_EXISTS){
			fprintf(stderr, "Cannot create directory: %s\n", ssh_get_error(session));
		}
	};
	FILE* fp;
	printf("Enter the filename to be transferred:");
	char* filename = malloc(100);
	fgets(filename, 100, stdin);
	filename[strcspn(filename, "\n")] = 0;
	fp = fopen(filename, "rb");
	if(fp==NULL){
		perror("Error opening requested file\n");
		free(filename);
		return SSH_ERROR;
	}
	fseek(fp, 0, SEEK_END);
	long fileSize = ftell(fp);
	rewind(fp);
	if(fileSize<=0){
		perror("Error getting file size\n");
		fclose(fp);
		free(filename);
		return SSH_ERROR;
	}
	char* buffer = malloc(fileSize);
	if(buffer==NULL){
		perror("Buffer creation failed\n");
		fclose(fp);
		free(filename);
		free(buffer);
		return SSH_ERROR;
	}
	size_t bytesRead = fread(buffer,1,fileSize,fp);
	if(bytesRead!=fileSize){
		perror("Error reading the file\n");
		free(buffer);
		free(filename);
		fclose(fp);
		return SSH_ERROR;
	}
	fclose(fp);
	int access_type = O_WRONLY | O_CREAT | O_TRUNC;
	char remotefilename[150];
	snprintf(remotefilename, 150, "upload/%s", filename);
	sftp_file file = sftp_open(sftp, remotefilename, access_type, S_IRWXU);
	if(file==NULL){
		fprintf(stderr, "Error creating destination file: %s\n", ssh_get_error(session));
		printf("%s\n", remotefilename);
		fprintf(stderr, "SFTP Error Code: %d\n", sftp_get_error(sftp));
		free(buffer);
		free(filename);
		return SSH_ERROR;
	}
	size_t nwritten = sftp_write(file, buffer, fileSize);
	if(nwritten!=fileSize){
		fprintf(stderr, "Error writing to file: %s\n", ssh_get_error(session));
		free(buffer);
		free(filename);
		return SSH_ERROR;
	}
	rc = sftp_close(file);
	if(rc!=SSH_OK){
		fprintf(stderr, "Error closing file copy: %s\n", ssh_get_error(session));
		free(buffer);
		free(filename);
		return rc;
	}
	free(buffer);
	free(filename);
	return SSH_OK;
}
int main(){
	char ip[100];
	printf("Enter remote host ip: ");
	fgets(ip, sizeof(ip), stdin);
	ip[strcspn(ip, "\n")] = 0;
	int port = 22;
	int verbosity = SSH_LOG_PROTOCOL;
	ssh_session my_ssh_session = ssh_new();
	if(my_ssh_session==NULL) exit(-1);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, ip);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
	int rc = ssh_connect(my_ssh_session);
	if(rc!=SSH_OK){
		fprintf(stderr, "Error connecting to local host: %s\n", ssh_get_error(my_ssh_session));
		exit(-1);
	}
	if(verify_knownhost(my_ssh_session)<0){
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}
	char* password;
	password = getpass("Password: ");
	rc = ssh_userauth_password(my_ssh_session, NULL, password);
	if(rc!=SSH_AUTH_SUCCESS){
		fprintf(stderr, "Error authenticating with password: %s\n", ssh_get_error(my_ssh_session));
		memset(password, 0, strlen(password));
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}
	rc = create_sftp_copy_session(my_ssh_session);
	if(rc!=SSH_OK){
		fprintf(stderr, "Errors in SFTP session: %d\n", rc);
	}
	memset(password, 0, strlen(password));
	ssh_disconnect(my_ssh_session);
	ssh_free(my_ssh_session);
}
