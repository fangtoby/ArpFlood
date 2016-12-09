#include <string.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <netinet/in.h>  
#include <error.h>  
#include <errno.h>  
  
#include <sys/types.h>  
#include <dirent.h>  
#include <sys/socket.h>  
#include <sys/stat.h>  
#include <unistd.h>  
#include <fcntl.h>  
  
// 建立socket 开始侦听 接收连接 接收客户端数据 解析http协议 发送文件数据给客户端  
  
#define HTTP_PORT "2010"  
#define MAX_CONNECTION 10  
#define DOCUMENT_ROOT "www"  
#define LOG_PATH "log/access.log"  
  
void parser(char *s,char res[][255],char host[][255]);  
static char *strtoupper( char *s );  
static long filesize(const char *filename);  
static int file_exists(const char *filename);  
static void mime_content_type( const char *name, char *ret );  
static int WriteLog( const char *message );  
static int is_dir(const char *filename);  
  
static unsigned short g_is_log        = 1;  
static int g_log_fd                    = 0;  
  
int main(void)  
{  
    int server_sock;  
    int client_sock;  
    struct sockaddr_in server_addr;  
    struct sockaddr_in client_addr;  
    struct sockaddr_in sin;  
    struct stat file_stat;  
    pid_t pid;  
    char client_ip[100];  
    char buf[20000];  
    char buf_all[2000];  
    char buf1[2000];  
    char p[3][255];  
    char h[3][255];  
    char tmp[2000];  
    char cwd[1024];  
    char filename[2000];  
    char filepath[2000];  
    int fd,size;  
    int currentConn = 0;  
      
    DIR * dir;  
    struct dirent * ptr;  
      
  
  
    chdir("../");  
      
    if ( (pid = fork()) < 0 )  
    {  
        perror("fork");  
        exit(1);  
    }  
    else if ( pid != 0)  
    {  
        exit(1);  
    }  
      
    if((server_sock = socket(AF_INET,SOCK_STREAM,0)) < 0)  
    {  
        perror("socket");  
        exit(1);  
    }  
      
    memset(&server_addr,0,sizeof(server_addr));  
    server_addr.sin_family = AF_INET;  
    server_addr.sin_port = htons(atoi(HTTP_PORT));  
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);  
      
    if(bind(server_sock,(struct sockaddr*)&server_addr,sizeof(server_addr)) < 0)  
    {  
        perror("bind");  
        exit(1);  
    }  
      
    if(listen(server_sock,MAX_CONNECTION) < 0)  
    {  
        perror("listen");  
        exit(1);  
    }  
      
    printf("fasthttp successful created ...\n");  
      
    while(1)  
    {  
        unsigned int clientlen = sizeof(client_addr);  
        if((client_sock = accept(server_sock,(struct sockaddr*)&client_addr,&clientlen)) < 0)  
        {  
            perror("accept");  
            exit(1);  
        }  
          
        if((pid = fork()) == 0)  
        {  
  
            if(read(client_sock,buf,20000) < 0)  
            {  
                perror("read data from client");  
                exit(1);  
            }  
              
            parser(buf,p,h);  
              
            if(strcmp(strtoupper(p[0]),"GET") != 0  
                && strcmp(strtoupper(p[0]),"POST") != 0  
                && strcmp(strtoupper(p[0]),"HEAD") != 0)  
            {  
                memset(&buf,0,sizeof(buf));  
                  
                sprintf(buf, "HTTP/1.1 501 Not Implemented\r\nServer: %s\r\nContent-Type: text/html\r\nContent-Length:    1489\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n", "Apache");  
                write(client_sock,buf,strlen(buf));  
                  
                memset(&buf,0,sizeof(buf));  
                sprintf(buf,"<h2>%s Method Not Implemented</h2>","501");  
                write(client_sock,buf,strlen(buf));  
                close(client_sock);  
                exit(0);  
            }  
               
            if(strcmp(p[1],"/") == 0)  
            {  
                memset(&tmp,0,sizeof(tmp));  
                sprintf(tmp,"%s","index.html");  
                strcat(p[1],tmp);  
            }  
              
            WriteLog(p[1]);  
            getcwd(filepath, sizeof(filepath));  
            strcat(filepath,"/");  
            strcat(filepath,DOCUMENT_ROOT);  
             strcat(filepath,p[1]);  
  
            if(!file_exists(filepath))  
            {  
                memset(&buf,0,sizeof(buf));  
                sprintf(buf, "HTTP/1.1 404 Not Found\r\nServer: %s\r\nContent-Type: text/html\r\nContent-Length:    257271\r\nConnection: close\r\n\r\n", "Apache");  
                write(client_sock,buf,strlen(buf));  
                  
                memset(&buf,0,sizeof(buf));  
                sprintf(buf,"<html><head><title>404 Not Found</title></head><body bgcolor=\"white\"><center><h1>404 Not Found</h1></center><hr><center>Powered by %s</center></body></html>","fasthttp");  
                write(client_sock,buf,strlen(buf));  
                close(client_sock);  
                  
                memset(&buf,0,sizeof(buf));  
                sprintf(buf,"404 Not Found\t%s\n",filepath);  
                WriteLog(buf);  
                  
                exit(0);  
            }  
              
            if(access(filepath,R_OK) < 0)  
            {  
                memset(&buf,0,sizeof(buf));  
                sprintf(buf, "HTTP/1.1 403 Forbidden\r\nServer: %s\r\nContent-Type: text/html\r\nContent-Length:    25727\r\nConnection: close\r\n\r\n", "Apache");  
                write(client_sock,buf,strlen(buf));  
                close(client_sock);  
                exit(0);  
            }  
              
             /** 目录列表 **/  
             if(is_dir(filepath))  
             {  
                memset(&tmp,0,sizeof(tmp));  
                sprintf(tmp,"<html><head><title>Index of %s</title></head><body><h1>Index of %s</h1><ul><li><a href=\"/\"> Parent Directory</a></li>",filepath,filepath);  
                strcat(buf,tmp);  
  
                 if((dir = opendir(filepath)) != NULL)  
                 {  
                     while((ptr = readdir(dir)) != NULL)  
                     {  
                           
                         if(strcmp(ptr->d_name,".") == 0 || strcmp(ptr->d_name,"..") == 0)  
                         {  
                             continue;      
                         }  
                           
                         memset(&buf,0,sizeof(buf));  
                         sprintf(buf,"%s/%s",filepath,ptr->d_name);  
                          
                        if(is_dir(buf))  
                        {  
                            memset(&buf,0,sizeof(buf));  
                            sprintf(buf,"<li><a href=\"%s/\"> %s/</a></li>",ptr->d_name,ptr->d_name);  
                        }  
                        else  
                        {  
                            memset(&buf,0,sizeof(buf));  
                            sprintf(buf,"<li><a href=\"%s\"> %s</a></li>",ptr->d_name,ptr->d_name);      
                        }  
                        strcat(tmp,buf);  
                     }  
                 }  
                 closedir(dir);  
  
                 memset(&buf,0,sizeof(buf));  
                sprintf(buf,"%s","</ul>");  
                strcat(tmp,buf);  
                  
                memset(&buf,0,sizeof(buf));  
                sprintf(buf, "HTTP/1.1 200 OK\r\nServer: fasthttp\r\nContent-Type: text/html;charset=utf-8\r\nContent-Length:    %d\r\nConnection: close\r\n\r\n", strlen(tmp));  
                write(client_sock,buf,strlen(buf));  
              
                write(client_sock,tmp,strlen(tmp));  
                close(client_sock);  
             }  
               
            memset(&tmp,0,sizeof(tmp));  
            mime_content_type(filepath,tmp);  
              
            memset(&buf,0,sizeof(buf));  
            sprintf(buf, "HTTP/1.1 200 OK\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length:    25727\r\nConnection: close\r\n\r\n", "Apache",tmp);  
            write(client_sock,buf,strlen(buf));  
              
              
              
            memset(&buf,0,sizeof(buf));  
            fd = open(filepath,O_RDONLY);  
            read(fd,buf,filesize(filepath));  
            close(fd);  
              
            write(client_sock,buf,filesize(filepath));  
            close(client_sock);  
              
            memset(&buf,0,sizeof(buf));  
            sprintf(buf,"200 OK\t%s\t%d\n",filepath,filesize(filepath));  
            WriteLog(buf);  
              
            exit(0);  
        }  
        else  
        {  
            wait(NULL);  
        }  
          
        close(client_sock);  
    }  
      
      
}  
  
void parser(char *s,char res[][255],char host[][255])  
{  
    int i,j = 0;  
    int n;  
    char hosts[255];  
  
    for (i = 0;s[i] != '\r';i++)        /* obtain the first line in http protocol head */  
        ;  
    s[i] = '\0';  
    n=i++;  
      
    for (i = 0,j = 0;i < 3;i++,j++)        /* divide the protocol head in blank */  
    {  
        strcpy(res[j],strsep(&s," "));  
    }  
      
    for(i=n;s[i] != '\r';i++)  
    {  
        strcat(hosts,s[i]);  
    }  
      
    for (i = 0,j = 0;i < 3;i++,j++)        /* divide the protocol head in blank */  
    {  
        strcpy(host[j],strsep(&hosts,":"));  
    }  
      
}  
  
/** 
 * strtoupper - string to upper 
 * 
 */  
static char *strtoupper( char *s )  
{  
    int i, len = sizeof(s);  
    for( i = 0; i < len; i++ )  
    {  
        s[i] = ( s[i] >= 'a' && s[i] <= 'z' ? s[i] + 'A' - 'a' : s[i] );  
    }  
      
    return(s);  
}  
  
/** 
 *  filesize - get file size 
 */  
static long filesize(const char *filename)  
{  
    struct stat buf;  
    if (!stat(filename, &buf))  
    {  
        return buf.st_size;  
    }  
    return 0;  
}  
  
/** 
 * file_exists - check file is exist 
 */  
static int file_exists(const char *filename)  
{  
    struct stat buf;  
      
    if (stat(filename, &buf) < 0)  
    {  
        if (errno == ENOENT)  
        {  
            return 0;  
        }  
    }  
    return 1;  
}  
  
/** 
 * Get MIME type header 
 * 
 */  
static void mime_content_type( const char *name, char *ret ){  
    char *dot, *buf;  
  
    dot = strrchr(name, '.');  
  
    /* Text */  
    if ( strcmp(dot, ".txt") == 0 ){  
        buf = "text/plain";  
    } else if ( strcmp( dot, ".css" ) == 0 ){  
        buf = "text/css";  
    } else if ( strcmp( dot, ".js" ) == 0 ){  
        buf = "text/javascript";  
    } else if ( strcmp(dot, ".xml") == 0 || strcmp(dot, ".xsl") == 0 ){  
        buf = "text/xml";  
    } else if ( strcmp(dot, ".xhtm") == 0 || strcmp(dot, ".xhtml") == 0 || strcmp(dot, ".xht") == 0 ){  
        buf = "application/xhtml+xml";  
    } else if ( strcmp(dot, ".html") == 0 || strcmp(dot, ".htm") == 0 || strcmp(dot, ".shtml") == 0 || strcmp(dot, ".hts") == 0 ){  
        buf = "text/html";  
  
    /* Images */  
    } else if ( strcmp( dot, ".gif" ) == 0 ){  
        buf = "image/gif";  
    } else if ( strcmp( dot, ".png" ) == 0 ){  
        buf = "image/png";  
    } else if ( strcmp( dot, ".bmp" ) == 0 ){  
        buf = "application/x-MS-bmp";  
    } else if ( strcmp( dot, ".jpg" ) == 0 || strcmp( dot, ".jpeg" ) == 0 || strcmp( dot, ".jpe" ) == 0 || strcmp( dot, ".jpz" ) == 0 ){  
        buf = "image/jpeg";  
  
    /* Audio & Video */  
    } else if ( strcmp( dot, ".wav" ) == 0 ){  
        buf = "audio/wav";  
    } else if ( strcmp( dot, ".wma" ) == 0 ){  
        buf = "audio/x-ms-wma";  
    } else if ( strcmp( dot, ".wmv" ) == 0 ){  
        buf = "audio/x-ms-wmv";  
    } else if ( strcmp( dot, ".au" ) == 0 || strcmp( dot, ".snd" ) == 0 ){  
        buf = "audio/basic";  
    } else if ( strcmp( dot, ".midi" ) == 0 || strcmp( dot, ".mid" ) == 0 ){  
        buf = "audio/midi";  
    } else if ( strcmp( dot, ".mp3" ) == 0 || strcmp( dot, ".mp2" ) == 0 ){  
        buf = "audio/x-mpeg";  
    } else if ( strcmp( dot, ".rm" ) == 0  || strcmp( dot, ".rmvb" ) == 0 || strcmp( dot, ".rmm" ) == 0 ){  
        buf = "audio/x-pn-realaudio";  
    } else if ( strcmp( dot, ".avi" ) == 0 ){  
        buf = "video/x-msvideo";  
    } else if ( strcmp( dot, ".3gp" ) == 0 ){  
        buf = "video/3gpp";  
    } else if ( strcmp( dot, ".mov" ) == 0 ){  
        buf = "video/quicktime";  
    } else if ( strcmp( dot, ".wmx" ) == 0 ){  
        buf = "video/x-ms-wmx";  
    } else if ( strcmp( dot, ".asf" ) == 0  || strcmp( dot, ".asx" ) == 0 ){  
        buf = "video/x-ms-asf";  
    } else if ( strcmp( dot, ".mp4" ) == 0 || strcmp( dot, ".mpg4" ) == 0 ){  
        buf = "video/mp4";  
    } else if ( strcmp( dot, ".mpe" ) == 0  || strcmp( dot, ".mpeg" ) == 0 || strcmp( dot, ".mpg" ) == 0 || strcmp( dot, ".mpga" ) == 0 ){  
        buf = "video/mpeg";  
  
    /* Documents */  
    } else if ( strcmp( dot, ".pdf" ) == 0 ){  
        buf = "application/pdf";  
    } else if ( strcmp( dot, ".rtf" ) == 0 ){  
        buf = "application/rtf";  
    } else if ( strcmp( dot, ".doc" ) == 0  || strcmp( dot, ".dot" ) == 0 ){  
        buf = "application/msword";  
    } else if ( strcmp( dot, ".xls" ) == 0  || strcmp( dot, ".xla" ) == 0 ){  
        buf = "application/msexcel";  
    } else if ( strcmp( dot, ".hlp" ) == 0  || strcmp( dot, ".chm" ) == 0 ){  
        buf = "application/mshelp";  
    } else if ( strcmp( dot, ".swf" ) == 0  || strcmp( dot, ".swfl" ) == 0 || strcmp( dot, ".cab" ) == 0 ){  
        buf = "application/x-shockwave-flash";  
    } else if ( strcmp( dot, ".ppt" ) == 0  || strcmp( dot, ".ppz" ) == 0 || strcmp( dot, ".pps" ) == 0 || strcmp( dot, ".pot" ) == 0 ){  
        buf = "application/mspowerpoint";  
  
    /* Binary & Packages */  
    } else if ( strcmp( dot, ".zip" ) == 0 ){  
        buf = "application/zip";  
    } else if ( strcmp( dot, ".rar" ) == 0 ){  
        buf = "application/x-rar-compressed";  
    } else if ( strcmp( dot, ".gz" ) == 0 ){  
        buf = "application/x-gzip";  
    } else if ( strcmp( dot, ".jar" ) == 0 ){  
        buf = "application/java-archive";  
    } else if ( strcmp( dot, ".tgz" ) == 0  || strcmp( dot, ".tar" ) == 0 ){  
        buf = "application/x-tar";  
    } else {  
        buf = "application/octet-stream";  
    }  
    strcpy(ret, buf);  
}  
  
/** 
 * Log message 
 * 
 */  
static int WriteLog( const char *message )  
{  
    if ( !g_is_log )  
    {  
        fprintf(stderr, "%s", message);  
        return 0;  
    }  
    if ( g_log_fd == 0 )  
    {  
        char g_log_path[2000];  
        getcwd(g_log_path, sizeof(g_log_path));  
        strcat(g_log_path,"/");  
        strcat(g_log_path,LOG_PATH);  
          
        if ( (g_log_fd = open(g_log_path, O_RDWR|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) == -1 )  
        {  
            perror("open log file error");  
            return -1;  
        }  
    }  
      
    if (write(g_log_fd, message, strlen(message)) == -1)  
    {  
        perror("write log error");  
        return -1;  
    }  
  
    return 0;  
}  
  
/** 
 * is_dir - check file is directory 
 * 
 */  
static int is_dir(const char *filename){  
    struct stat buf;  
    if ( stat(filename, &buf) < 0 ){  
        return -1;  
    }  
    if (S_ISDIR(buf.st_mode)){  
        return 1;  
    }  
    return 0;  
}  
