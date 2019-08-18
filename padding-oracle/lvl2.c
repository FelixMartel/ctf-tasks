#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void init_openssl()
{
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
  EVP_cleanup();
}

int main(int argc, char **argv) {
  char* hostname = NULL;
  char* flag = "flag{usin_yo0ur_k3y_liek_its_m4_0wn}";
  size_t hostnamesize = 0;

  puts("Hi :), I like to send my secrets on port 4433\nWhat is your hostname?");
  if(getline(&hostname, &hostnamesize, stdin) == -1) {
    free(hostname);
    exit(1);
  }

  BIO* certbio = BIO_new(BIO_s_file());
  if(certbio == NULL) exit(1);
  int res = BIO_read_filename(certbio, "cert.pem");
  if(res != 1) exit(1);
  X509* cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
  if(cert == NULL) exit(1);
  EVP_PKEY* CAkey = X509_get_pubkey(cert);
  if(CAkey == NULL) exit(1);
  BIO_free(certbio);

  init_openssl();

  const SSL_METHOD* method = SSLv23_client_method();
  if(method == NULL) exit(1);

  SSL_CTX* ctx = SSL_CTX_new(method);
  if(ctx == NULL) exit(1);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION);

  BIO* remote = BIO_new_ssl_connect(ctx);
  if(remote == NULL) exit(1);

  size_t hostnamelen = strlen(hostname);
  if(hostname[hostnamelen-1] == '\n') {
    hostname[hostnamelen-1] = '\0';
    hostnamelen -= 1;
  }
  if(hostnamesize < hostnamelen + 5)
    hostname = realloc(hostname, hostnamesize + 5);
  strcat(hostname,":4433");
  res = BIO_set_conn_hostname(remote, hostname);
  if(res != 1) exit(1);

  SSL *ssl = NULL;
  BIO_get_ssl(remote, &ssl);
  if(ssl == NULL) exit(1);

  res = SSL_set_cipher_list(ssl, "aRSA:!kRSA");
  if(res != 1) exit(1);

  puts("Ok!");
  res = BIO_do_connect(remote);
  if(res != 1) {
    ERR_print_errors_fp(stderr);
    puts("Awkward handshakes dont deserve my secrets");
    exit(1);
  }

  puts("Nice to meet you, lets shake hands");
  res = BIO_do_handshake(remote);
  if(res != 1) {
    ERR_print_errors_fp(stderr);
    puts("Awkward handshakes dont deserve my secrets");
    exit(1);
  }

  X509* servercert = SSL_get_peer_certificate(ssl);
  if(servercert == NULL) exit(1);
  EVP_PKEY* key = X509_get_pubkey(servercert);
  if(key == NULL) exit(1);
  if(EVP_PKEY_cmp(key, CAkey) != 1) {
    puts("Cant fool me");
    exit(1);
  }

  BIO_puts(remote, flag);

  puts("What a grip!");

  BIO_free_all(remote);
  SSL_CTX_free(ctx);
  cleanup_openssl();
  free(hostname);
}
