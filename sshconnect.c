#include <stdio.h>
#include <stdlib.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gtk/gtk.h>

GtkWidget *entry_host, *entry_filename, *entry_pass, *status_label;

ssh_session my_ssh_session = NULL;

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


void on_connect_clicked(GtkWidget *widget, gpointer data){
	const char* ip = gtk_entry_get_text(GTK_ENTRY(entry_host));
	const char* password = gtk_entry_get_text(GTK_ENTRY(entry_pass));
	if(strlen(ip)==0 || strlen(password)==0){
		gtk_label_set_text(GTK_LABEL(status_label), "Error: ALL FIELDS MUST BE FILLED");
	}
	int port = 22;
	int verbosity = SSH_LOG_PROTOCOL;
	my_ssh_session = ssh_new();
	if(my_ssh_session==NULL) exit(-1);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, ip);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "ramsundar");
	ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
	int rc = ssh_connect(my_ssh_session);
	if(rc!=SSH_OK){
		fprintf(stderr, "Error connecting to local host: %s\n", ssh_get_error(my_ssh_session));
		return;
	}
	if(verify_knownhost(my_ssh_session)<0){
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		return;
	}
	rc = ssh_userauth_password(my_ssh_session, NULL, password);
	if(rc!=SSH_AUTH_SUCCESS){
		fprintf(stderr, "Error authenticating with password: %s\n", ssh_get_error(my_ssh_session));
		memset(password, 0, strlen(password));
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		my_ssh_session = NULL;
		return;
	}
	gtk_label_set_text(GTK_LABEL(status_label), "Connected successfully");
}

void on_upload_clicked(GtkWidget *widget, gpointer data){
	const char* filename = gtk_entry_get_text(GTK_ENTRY(entry_filename));
	if(!my_ssh_session){
		gtk_label_set_text(GTK_LABEL(status_label), "Error: No active SSH Session");
		return;
	}
	sftp_session sftp;
	int rc;
	sftp = sftp_new(my_ssh_session);
	if(sftp==NULL){
		fprintf(stderr, "Error establishing an SFTP session: %s\n", ssh_get_error(my_ssh_session));
		return;
	}
	rc = sftp_init(sftp);
	if(rc!=SSH_OK){
		fprintf(stderr, "Error initialising SFTP session: Code %d\n", sftp_get_error(sftp));
		sftp_free(sftp);
	}
	sftp_attributes dir_stat = sftp_stat(sftp, "upload");
	if(!dir_stat){
		rc = sftp_mkdir(sftp, "upload",  S_IRWXU);
		if(rc!=SSH_OK){
			if(sftp_get_error(sftp) != SSH_FX_FILE_ALREADY_EXISTS){
				fprintf(stderr, "Cannot create directory: %s\n", ssh_get_error(my_ssh_session));
			}
		}
	}
	FILE* fp;
	fp = fopen(filename, "rb");
	if(fp==NULL){
		perror("Error opening requested file\n");
	}
	fseek(fp, 0, SEEK_END);
	long fileSize = ftell(fp);
	rewind(fp);
	if(fileSize<=0){
		perror("Error getting file size\n");
		fclose(fp);
		return;
	}
	char* buffer = malloc(fileSize);
	if(buffer==NULL){
		perror("Buffer creation failed\n");
		fclose(fp);
		free(buffer);
		return;
	}
	size_t bytesRead = fread(buffer,1,fileSize,fp);
	if(bytesRead!=fileSize){
		perror("Error reading the file\n");
		free(buffer);
		fclose(fp);
		return;
	}
	fclose(fp);
	int access_type = O_WRONLY | O_CREAT | O_TRUNC;
	char remotefilename[150];
	snprintf(remotefilename, 150, "upload/%s", filename);
	sftp_file file = sftp_open(sftp, remotefilename, access_type, S_IRWXU);
	if(file==NULL){
		fprintf(stderr, "Error creating destination file: %s\n", ssh_get_error(my_ssh_session));
		printf("%s\n", remotefilename);
		fprintf(stderr, "SFTP Error Code: %d\n", sftp_get_error(sftp));
		free(buffer);
		return;
	}
	size_t nwritten = sftp_write(file, buffer, fileSize);
	if(nwritten!=fileSize){
		fprintf(stderr, "Error writing to file: %s\n", ssh_get_error(my_ssh_session));
		free(buffer);
		return;
	}
	rc = sftp_close(file);
	if(rc!=SSH_OK){
		fprintf(stderr, "Error closing file copy: %s\n", ssh_get_error(my_ssh_session));
		free(buffer);
		return;
	}
	free(buffer);
	sftp_free(sftp);
	gtk_label_set_text(GTK_LABEL(status_label), "File uploaded successfully!");
}

GtkWidget* create_ssh_ui(){
	GtkWidget *window, *grid, *button_connect, *button_upload;
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(window), "SFTP CLIENT");
	gtk_window_set_default_size(GTK_WINDOW(window), 400, 200);
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	grid = gtk_grid_new();
	gtk_container_add(GTK_CONTAINER(window), grid);
	GtkWidget *label_host = gtk_label_new("Host:");
	GtkWidget *label_pass = gtk_label_new("Password:");
	GtkWidget *label_filename = gtk_label_new("File Name to Upload:");
	status_label = gtk_label_new("Status: Not Connected");
	entry_host = gtk_entry_new();
	entry_pass = gtk_entry_new();
	entry_filename = gtk_entry_new();
	gtk_entry_set_visibility(GTK_ENTRY(entry_pass), FALSE);
	button_connect = gtk_button_new_with_label("Connect To Host");
	button_upload = gtk_button_new_with_label("Upload File");
	g_signal_connect(button_connect, "clicked", G_CALLBACK(on_connect_clicked), NULL);
	g_signal_connect(button_upload, "clicked", G_CALLBACK(on_upload_clicked), NULL);
	gtk_grid_attach(GTK_GRID(grid), label_host, 0,0,1,1);
	gtk_grid_attach(GTK_GRID(grid), entry_host, 1,0,1,1);
	gtk_grid_attach(GTK_GRID(grid), label_pass, 0,1,1,1);
	gtk_grid_attach(GTK_GRID(grid), entry_pass, 1,1,1,1);
	gtk_grid_attach(GTK_GRID(grid), button_connect, 0,2,2,1);
	gtk_grid_attach(GTK_GRID(grid), status_label, 0,3,2,1);
	gtk_grid_attach(GTK_GRID(grid), label_filename, 0,4,1,1);
	gtk_grid_attach(GTK_GRID(grid), entry_filename, 1,4,1,1);
	gtk_grid_attach(GTK_GRID(grid), button_upload, 0,5,2,1);
	return window;
}

int main(int argc, char* argv[]){
	gtk_init(&argc, &argv);
	GtkWidget *window = create_ssh_ui();
	gtk_widget_show_all(window);
	gtk_main();
	return 0;
}
