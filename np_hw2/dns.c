#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <regex.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_LENGTH 256

#define A     1
#define NS    2
#define CNAME 5
#define SOA   6
#define MX    15
#define TXT   16
#define AAAA  28

typedef struct header{
    int16_t id;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t rd : 1;
    u_int16_t tc : 1;
    u_int16_t aa : 1;
    u_int16_t opcode : 4;
    u_int16_t qr : 1;
    u_int16_t rcode : 4;
    u_int16_t z : 3;
    u_int16_t ra : 1;

#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t qr : 1;
    u_int16_t opcode : 4;
    u_int16_t aa : 1;
    u_int16_t tc : 1;
    u_int16_t rd : 1;
    u_int16_t ra : 1;
    u_int16_t z : 3;
    u_int16_t rcode : 4;
#endif
    u_int16_t qdcount;
    u_int16_t ancount;
    u_int16_t nscount;
    u_int16_t arcount;
}__attribute__((packed)) Header;

typedef struct question{
    u_int8_t *qname;
    u_int16_t qtype;
    u_int16_t qclass;
}__attribute__((packed)) Question;

typedef struct record{
    u_int8_t *name;
    u_int16_t type;
    u_int16_t class;
    u_int32_t ttl;
    u_int16_t rdlength;
    u_int8_t *rdata;
}__attribute__((packed)) Record;

typedef struct soa_rdata{
    u_int8_t *mname;
    u_int8_t *rname;
    u_int32_t serial;
    u_int32_t refresh;
    u_int32_t retry;
    u_int32_t expire;
    u_int32_t minimum;
}__attribute__((packed)) SOA_rdata;

typedef struct ms_rdata{
    u_int16_t preference;
    u_int8_t *exchange;
}__attribute__((packed)) MX_rdata;

void print_header(Header *h){
    printf("-------------------------------------\n");
    printf("h->id: %u\n", ntohs(h->id));
    printf("h->qr: %u\n", h->qr);
    printf("h->opcode: %u\n", h->opcode);
    printf("h->aa: %u\n", h->aa);
    printf("h->tc: %u\n", h->tc);
    printf("h->rd: %u\n", h->rd);
    printf("h->ra: %u\n", h->ra);
    printf("h->z: %u\n", h->z);
    printf("h->rcode: %u\n", h->rcode);
    printf("h->qdcount: %u\n", ntohs(h->qdcount));
    printf("h->ancount: %u\n", ntohs(h->ancount));
    printf("h->nscount: %u\n", ntohs(h->nscount));
    printf("h->arcount: %u\n", ntohs(h->arcount));
    return;
}

void print_question(Question *q){
    printf("-------------------------------------\n");
    printf("q->qname: %s\n", q->qname);
    printf("q->qtype: %u\n", ntohs(q->qtype));
    printf("q->qclass: %u\n", ntohs(q->qclass));
    return;
}

void print_record(Record *r){
    printf("-------------------------------------\n");
    printf("r->name: %s\n", r->name);
    printf("r->type: %u\n", ntohs(r->type));
    printf("r->class: %u\n", ntohs(r->class));
    printf("r->ttl: %u\n", ntohl(r->ttl));
    printf("r->rdlength: %u\n", ntohs(r->rdlength));
    printf("r->rdata: %s\n", r->rdata);
    return;
}

int parse_qname(u_int8_t *buffer_ptr, u_int8_t *qname, char *domain){
    int len = 0, pos = 0;
    qname[len++] = *buffer_ptr;
    buffer_ptr++; 
    while(*buffer_ptr != '\0'){
        char curr_char = *((char *)buffer_ptr);
        if(curr_char >= '0' && curr_char <= '9' || curr_char >= 'A' && curr_char <= 'Z' || curr_char >= 'a' && curr_char <= 'z'){
            domain[pos++] = curr_char; 
        }else{
            domain[pos++] = '.';
        }
        qname[len++] = *buffer_ptr;
        buffer_ptr++;
    }
    domain[pos++] = '.';
    return len + 1;
}

int compress_name(u_int8_t *buffer, char *domain){
    int len = 0;
    char **parse_domain = (char **)calloc(5, sizeof(char *));
    for(int i = 0; i < 5; ++i){
        parse_domain[i] = (char *)calloc(32, sizeof(char));
    }
    const char period_delim[2] = ".";
    int cnt = 0;
    char *token = strtok(domain, period_delim);
    while(token != NULL){
        strcpy(parse_domain[cnt++], token);
        token = strtok(NULL, period_delim);
    }
    for(int i = 0; i < cnt; ++i){
        buffer[len++] = (u_int8_t)strlen(parse_domain[i]);
        for(int j = 0; j < strlen(parse_domain[i]); ++j){
            buffer[len++] = (u_int8_t)(parse_domain[i][j]);
        }
    }
    buffer[len++] = '\0';
    for(int i = 0; i < 5; ++i){
        free(parse_domain[i]);
    }
    free(parse_domain);
    return len;
}

int compress_text(u_int8_t *buffer, char *text){
    int len = 0;
    char *cp_text = (char *)calloc(64, sizeof(char));
    strncpy(cp_text, text+1 ,strlen(text)-2);
    buffer[len++] = (u_int8_t)strlen(cp_text);
    char *text_ptr = cp_text;
    while(*text_ptr != '\0'){
        buffer[len++] = *((u_int8_t *)text_ptr);
        text_ptr++;
    }
    return len;
}

int main(int argc, char* argv[]){
    if(argc < 3){
        printf("usage: ./dns <port-number> <path-to-the-config-file>\n");
        return 1;
    }
    struct sockaddr_in serv_addr;
    int sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock_fd == -1){
        printf("Cannot setup a socket!\n");
        return 1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(atoi(argv[1]));
    if(bind(sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1){
        printf("Socket bind failed!\n");
        return 1;
    }

    struct sockaddr_in proxy_addr;
    socklen_t proxy_addr_len = sizeof(proxy_addr);
    int proxy_sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(proxy_sock_fd == -1){
        printf("Cannot setiup proxy socket!\n");
        return 1;
    }
    
    struct sockaddr_in cli_addr;
    socklen_t cli_addr_len = sizeof(cli_addr);

    char *query_buff = (char *)calloc(512, sizeof(char));
    printf("DNS server running...\n");
    while(true){
        ssize_t rd_sz = recvfrom(sock_fd, query_buff, 512, 0, (struct sockaddr *)&cli_addr, &cli_addr_len);
        Header *header = (Header *)query_buff;
        print_header(header);
        Question question;
        question.qname = (u_int8_t *)calloc(128, sizeof(u_int8_t));
        char* domain_name = (char *)calloc(128, sizeof(char));
        int qname_len = parse_qname(query_buff + sizeof(Header), question.qname, domain_name);
        question.qname = (u_int8_t *)realloc(question.qname, qname_len);
        domain_name = (char *)realloc(domain_name, strlen(domain_name));

        printf("Parsed domain name: %s\n", domain_name);
        question.qtype = *((u_int16_t *)(query_buff + sizeof(Header) + qname_len)); 
        question.qclass = *((u_int16_t *)(query_buff + sizeof(Header) + qname_len + 2));
        print_question(&question);

        FILE *fp = fopen(argv[2], "r");
        if(fp == NULL){
            printf("Cannot open config file!\n");
            return 1;
        }
        size_t ip_size = 32;
        // need to handle \r\n problem
        char *forward_ip = (char *)calloc(ip_size, sizeof(char));
        int read_len = getline(&forward_ip, &ip_size, fp);
        int forward_ip_length = strlen(forward_ip);
        if(forward_ip[forward_ip_length-1] == '\n')
            forward_ip[forward_ip_length-1] = '\0';
        if(forward_ip[forward_ip_length-2] == '\r')
            forward_ip[forward_ip_length-2] = '\0';

        printf("Forward ip: %s\n", forward_ip);

        ssize_t dns_record_length = 32, zone_file_length = 32;
        char *dns_info = (char *)calloc(dns_record_length, sizeof(char));
        char *zone_file = (char *)calloc(zone_file_length, sizeof(char));
        
        bool is_subdomain = false;
        char *subdomain = (char *)calloc(16, sizeof(char));
        bool in_config = false;
        while((read_len = getline(&dns_info, &dns_record_length, fp)) != -1){
            char *comma = strchr(dns_info, ',');
            int domain_length = comma - dns_info;

            char *search_domain_name = (char *)calloc(dns_record_length, sizeof(char));
            strncpy(search_domain_name, dns_info, domain_length);
            printf("Search domain name: %s\n", search_domain_name);
            
            if(strcmp(search_domain_name, domain_name) == 0){
                // not subdomain (full match)
                int start_of_zonefile = comma - dns_info + 1;
                strcpy(zone_file, dns_info + start_of_zonefile);
                in_config = true;
                break;
            }else{
                // may be subdomain (check partial match)
                char *period = strchr(domain_name, '.');
                int subdomain_length = period - domain_name;
                strncpy(subdomain, domain_name, subdomain_length);

                int start_main_domain = period - domain_name + 1;
                if(strcmp(search_domain_name, domain_name + start_main_domain) == 0){
                    is_subdomain = true;
                    printf("Found Subdomain, the main domain name is: %s\n", domain_name + start_main_domain); 
                    printf("Found Subdomain, the subdomain name is %s\n", subdomain);
                    int start_of_zonefile = comma - dns_info + 1;
                    strcpy(zone_file, dns_info + start_of_zonefile);
                    in_config = true;
                    break;
                }
            }
        }

        if(!in_config){
            regex_t preg;
            const char *pattern = "^([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}).([0-9a-zA-Z]{1,61}.)*$";
            int success = regcomp(&preg, pattern, REG_EXTENDED | REG_ICASE);
            int status;
            if(success == 0){
                regmatch_t match_ptr[1];
                const size_t nmatch = 1;
                status = regexec(&preg, domain_name, nmatch, match_ptr, 0);
            }
            if(status == 0){
                // not in config but match regular expression -> nip.io
                const char period_delim[2] = ".";
                char **parse_ip = (char **)calloc(6, sizeof(char *));
                for(int i = 0; i < 6; ++i){
                    parse_ip[i] = (char *)calloc(64, sizeof(char));
                }
                int reg_cnt = 0;
                char *reg_token = strtok(domain_name, period_delim);
                while(reg_token != NULL){
                    strcpy(parse_ip[reg_cnt++], reg_token);
                    reg_token = strtok(NULL, period_delim);
                }
                char *reg_ip = (char *)calloc(20, sizeof(char));
                for(int i = 0; i < 4; ++i){ 
                    strcat(reg_ip, parse_ip[i]);
                    if(i != 3)
                        strcat(reg_ip, ".");
                }
                printf("Reg ip: %s\n", reg_ip);
                char *answer_buff = (char *)calloc(512, sizeof(char));

                Header *return_header = (Header *)answer_buff;
                return_header->id = header->id;
                return_header->qr = 1;
                return_header->opcode = 0;
                return_header->aa = 1;
                return_header->tc = 0;
                return_header->rd = 1;
                return_header->z = 0;
                return_header->rcode = 0;
                return_header->qdcount = htons(1);
                return_header->ancount = htons(1);
                return_header->nscount = htons(0);
                return_header->arcount = htons(0);

                Question return_question;
                for(int j = 0; j < qname_len; ++j){
                    return_question.qname = (u_int8_t *)(answer_buff + sizeof(Header) + j);
                    *return_question.qname = question.qname[j];
                }

                return_question.qtype = htons(1);
                u_int16_t *qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                *qtype_ptr = return_question.qtype;

                return_question.qclass = htons(1);
                u_int16_t *qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                *qclass_ptr = return_question.qclass;

                Record return_answer;
                for(int j = 0; j < qname_len; ++j){
                    return_answer.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                    *return_answer.name = question.qname[j];
                }

                return_answer.type = htons(1);
                u_int16_t *ans_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len);
                *ans_type_ptr = return_answer.type;

                return_answer.class = htons(1);
                u_int16_t *ans_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 2);
                *ans_class_ptr = return_answer.class;

                return_answer.ttl = htonl(1);
                u_int32_t *ans_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 4);
                *ans_ttl_ptr = return_answer.ttl;

                return_answer.rdlength = htons(4);
                u_int16_t *ans_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 8);
                *ans_rdlength_ptr = return_answer.rdlength;

                u_int32_t a_rdata = inet_addr(reg_ip);
                u_int8_t *convert_addr = (u_int8_t *)&a_rdata;
                for(int j = 0; j < 4; ++j){
                    return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + j);
                    *return_answer.rdata = convert_addr[j];
                }
                ssize_t wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + qname_len + 10 + 4, 0, (struct sockaddr *)&cli_addr, cli_addr_len);

            }else if(status == REG_NOMATCH){
                // not in config and not match regular expression -> forwarded ip 
                proxy_addr.sin_family = AF_INET;
                proxy_addr.sin_addr.s_addr = inet_addr(forward_ip);
                proxy_addr.sin_port = htons(53);

                char *proxy_answer_buff = (char *)calloc(512, sizeof(char));
                ssize_t proxy_wr_sz = sendto(proxy_sock_fd, query_buff, rd_sz, 0, (struct sockaddr *)&proxy_addr, proxy_addr_len);
                ssize_t proxy_rd_sz = recvfrom(proxy_sock_fd, proxy_answer_buff, 512, 0, (struct sockaddr *)&proxy_addr, &proxy_addr_len); 
                
                ssize_t wr_sz = sendto(sock_fd, proxy_answer_buff, proxy_rd_sz, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
            }

        }else{
            int origin_zonefile_length = strlen(zone_file);
            if(zone_file[origin_zonefile_length-1] == '\n')
                zone_file[origin_zonefile_length-1] = '\0';
            if(zone_file[origin_zonefile_length-2] == '\r')
                zone_file[origin_zonefile_length-2] = '\0';
            
            zone_file = (char *)realloc(zone_file, strlen(zone_file));
            fclose(fp);

            FILE* zone_fp = fopen(zone_file, "r");
            if(zone_fp == NULL){
                printf("Cannot open zone file!\n");
                return 1;
            }

            char *answer_buff = (char *)calloc(512, sizeof(char));
            u_int16_t q_type = ntohs(question.qtype);

            ssize_t zone_file_data_length = 256;
            int read_zone_file_data_length;
            char *zone_file_data;
            char **soa_data, **a_data, **aaaa_data, **ns_data, **mx_data, **cname_data, **txt_data;
            
            Header *return_header;
            Question return_question;
            u_int16_t *qtype_ptr, *qclass_ptr;

            Record return_answer;
            u_int16_t *ans_type_ptr, *ans_class_ptr, *ans_rdlength_ptr;
            u_int32_t ans_ttl;
            u_int32_t *ans_ttl_ptr;
            
            Record return_authority;
            u_int16_t *auth_type_ptr, *auth_class_ptr, *auth_rdlength_ptr;
            u_int32_t auth_ttl;
            u_int32_t *auth_ttl_ptr;

            Record return_additional;
            u_int16_t *add_type_ptr, *add_class_ptr, *add_rdlength_ptr;
            u_int32_t add_ttl;
            u_int32_t *add_ttl_ptr;

            u_int32_t a_rdata;
            u_int8_t *convert_addr;
            u_int32_t aaaa_rdata;
            u_int8_t *ns_rdata;
            u_int8_t *cname_rdata;
            u_int8_t *txt_rdata;
            SOA_rdata soa_rdata;
            MX_rdata mx_rdata;

            int ans_addr_len, auth_addr_len, add_addr_len;
            char *token;
            ssize_t wr_sz;

            const char space_delim[2] = " ";
            const char comma_delim[2] = ",";
            u_int8_t *ns_name, *soa_name, *mx_name;
            int auth_name_len, ans_name_len;
            char *main_domain_name;

            switch(q_type){
                case A:         
                    zone_file_data = (char *)calloc(zone_file_data_length, sizeof(char));
                    // initialize 2d array to store SOA(authority) resource record
                    soa_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store A(answer) resource record
                    a_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store CNAME(answer) resource record
                    cname_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store NS(authority) resource record
                    ns_data = (char **)calloc(5, sizeof(char *));
                    for(int i = 0; i < 5; ++i){
                        soa_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        a_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        cname_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        ns_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                    }                

                    bool has_type_a = false, has_type_a_cname = false;
                    // retrieve the domain name in the first line of zone-file
                    read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp);
                    
                    
                    read_zone_file_data_length = strlen(zone_file_data);
                    if(zone_file_data[read_zone_file_data_length-1] == '\n')
                        zone_file_data[read_zone_file_data_length-1] = '\0';
                    if(zone_file_data[read_zone_file_data_length-2] == '\r')
                        zone_file_data[read_zone_file_data_length-2] = '\0';

                    main_domain_name = (char *)calloc(32, sizeof(char));
                    strcpy(main_domain_name, zone_file_data);

                    while((read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp)) != -1){
                        read_zone_file_data_length = strlen(zone_file_data);
                        if(zone_file_data[read_zone_file_data_length-1] == '\n')
                            zone_file_data[read_zone_file_data_length-1] = '\0';
                        if(zone_file_data[read_zone_file_data_length-2] == '\r')
                            zone_file_data[read_zone_file_data_length-2] = '\0';
                        // check if there is (@, A) in the string
                        // also store SOA, A and NS resource record in advance
                        char **parsed_zone_file_data = (char **)calloc(5, sizeof(char *));
                        for(int j = 0; j < 5; ++j){
                            parsed_zone_file_data[j] = (char *)calloc(zone_file_data_length, sizeof(char));
                        }
                        int cnt = 0;
                        token = strtok(zone_file_data, comma_delim);
                        while(token != NULL){
                            strcpy(parsed_zone_file_data[cnt++], token);
                            token = strtok(NULL, comma_delim);
                        }
                        // retrieve (@, SOA)
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "SOA") == 0){
                            for(int j = 0; j < 5; ++j){
                                strcpy(soa_data[j], parsed_zone_file_data[j]);
                            }
                        }
                        // retrieve (@, NS) 
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "NS") == 0){
                            for(int j = 0; j < 5; ++j){
                                strcpy(ns_data[j], parsed_zone_file_data[j]);
                            }
                        }

                        if(is_subdomain){
                            // retrieve (subdomain, A)
                            char *cname_subdomain;
                            if(strcmp(parsed_zone_file_data[0], subdomain) == 0 && strcmp(parsed_zone_file_data[3], "A") == 0){
                                has_type_a = true;
                                for(int j = 0; j < 5; ++j){
                                    strcpy(a_data[j], parsed_zone_file_data[j]);        
                                }     
                            }else if(strcmp(parsed_zone_file_data[0], subdomain) == 0 && strcmp(parsed_zone_file_data[3], "CNAME") == 0){
                                has_type_a_cname = true;
                                for(int j = 0; j < 5; ++j){
                                    strcpy(cname_data[j], parsed_zone_file_data[j]);
                                }
                                char *period = strchr(parsed_zone_file_data[4], '.');
                                int len = period - parsed_zone_file_data[4];
                                cname_subdomain = (char *)calloc(zone_file_data_length, sizeof(char));
                                strncpy(cname_subdomain, parsed_zone_file_data[4], len);
                            }
                            if(has_type_a_cname){
                                printf("Cname_subdomain: %s\n", cname_subdomain);
                                if(strcmp(parsed_zone_file_data[0], cname_subdomain) == 0 && strcmp(parsed_zone_file_data[3], "A") == 0){
                                    has_type_a = true;
                                    for(int j = 0; j < 5; ++j){
                                        strcpy(a_data[j], parsed_zone_file_data[j]);
                                    }
                                } 
                            }
                        }else{
                            // retrieve (@, A)
                            if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "A") == 0){
                                has_type_a = true;
                                for(int j = 0; j < 5; ++j){
                                    strcpy(a_data[j], parsed_zone_file_data[j]);
                                }
                            }
                        }
                    }

                    // return answer A and authority NS if found in zone-file
                    if(has_type_a){
                        return_header = (Header *)answer_buff;
                        return_header->id = header->id;
                        return_header->qr = 1;
                        return_header->opcode = 0;
                        return_header->aa = 1;
                        return_header->tc = 0;
                        return_header->rd = 1;
                        return_header->ra = 0;
                        return_header->z = 0;
                        return_header->rcode = 0;
                        return_header->qdcount = htons(1);
                        if(has_type_a_cname){
                            return_header->ancount = htons(2);
                        }else{
                            return_header->ancount = htons(1);
                        }
                        return_header->nscount = htons(1);
                        return_header->arcount = htons(0);

                        for(int j = 0; j < qname_len; ++j){
                            return_question.qname = (u_int8_t *)(answer_buff + sizeof(Header) + j);
                            *return_question.qname = question.qname[j];
                        }

                        return_question.qtype = htons(1);
                        qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                        *qtype_ptr = return_question.qtype;

                        return_question.qclass = htons(1);
                        qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                        *qclass_ptr = return_question.qclass;

                        if(has_type_a_cname){

                            for(int j = 0; j < qname_len; ++j){
                                return_answer.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                                *return_answer.name = question.qname[j];
                            }

                            return_answer.type = htons(5);
                            ans_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len);
                            *ans_type_ptr = return_answer.type;

                            return_answer.class = htons(1);
                            ans_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 2);
                            *ans_class_ptr = return_answer.class;

                            ans_ttl = (u_int32_t)atoi(cname_data[1]);
                            return_answer.ttl = htonl(ans_ttl);
                            ans_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 4);
                            *ans_ttl_ptr = return_answer.ttl;

                            cname_rdata = (u_int8_t *)calloc(32, sizeof(u_int8_t)); 
                            ans_addr_len = compress_name(cname_rdata, cname_data[4]);

                            return_answer.rdlength = htons(ans_addr_len);
                            ans_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 8);
                            *ans_rdlength_ptr = return_answer.rdlength;

                            for(int j = 0; j < ans_addr_len; ++j){
                                return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + j);
                                *return_answer.rdata = cname_rdata[j];
                            } 

                            for(int j = 0; j < ans_addr_len; ++j){
                                return_answer.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + j);
                                *return_answer.name = cname_rdata[j];
                            }

                            return_answer.type = htons(1);
                            ans_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len);
                            *ans_type_ptr = return_answer.type;

                            return_answer.class = htons(1);
                            ans_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 2);
                            *ans_class_ptr = return_answer.class;

                            ans_ttl = (u_int32_t)atoi(a_data[1]);
                            return_answer.ttl = htonl(ans_ttl);
                            ans_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 4);
                            *ans_ttl_ptr = return_answer.ttl;

                            return_answer.rdlength = htons(4);
                            ans_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 8);
                            *ans_rdlength_ptr = return_answer.rdlength;

                            a_rdata = inet_addr(a_data[4]);
                            convert_addr = (u_int8_t *)&a_rdata;
                            for(int j = 0; j < 4; ++j){
                                return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + j);
                                *return_answer.rdata = convert_addr[j];
                            }

                            ns_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                            auth_name_len = compress_name(ns_name, main_domain_name);
                            for(int j = 0; j < auth_name_len; ++j){
                                return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 4 + j);
                                *return_authority.name = ns_name[j];
                            }

                            return_authority.type = htons(2); 
                            auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 4 + auth_name_len);
                            *auth_type_ptr = return_authority.type;

                            return_authority.class = htons(1);
                            auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 4 + auth_name_len + 2);
                            *auth_class_ptr = return_authority.class;

                            auth_ttl = (u_int32_t)atoi(ns_data[1]);
                            return_authority.ttl = htonl(auth_ttl);
                            auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 4 + auth_name_len + 4);
                            *auth_ttl_ptr = return_authority.ttl;

                            ns_rdata = (u_int8_t *)calloc(32, sizeof(u_int8_t)); 
                            auth_addr_len = compress_name(ns_rdata, ns_data[4]);

                            return_authority.rdlength = htons(auth_addr_len);
                            auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 4 + auth_name_len + 8);
                            *auth_rdlength_ptr = return_authority.rdlength;

                            for(int j = 0; j < auth_addr_len; ++j){
                                return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 4 + auth_name_len + 10 + j);
                                *return_authority.rdata = ns_rdata[j];
                            } 

                            wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 4 + auth_name_len + 10 + auth_addr_len, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                        }else{
                            for(int j = 0; j < qname_len; ++j){
                                return_answer.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                                *return_answer.name = question.qname[j];
                            }

                            return_answer.type = htons(1);
                            ans_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len);
                            *ans_type_ptr = return_answer.type;

                            return_answer.class = htons(1);
                            ans_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 2);
                            *ans_class_ptr = return_answer.class;

                            ans_ttl = (u_int32_t)atoi(a_data[1]);
                            return_answer.ttl = htonl(ans_ttl);
                            ans_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 4);
                            *ans_ttl_ptr = return_answer.ttl;

                            return_answer.rdlength = htons(4);
                            ans_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 8);
                            *ans_rdlength_ptr = return_answer.rdlength;

                            a_rdata = inet_addr(a_data[4]);
                            convert_addr = (u_int8_t *)&a_rdata;
                            for(int j = 0; j < 4; ++j){
                                return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + j);
                                *return_answer.rdata = convert_addr[j];
                            }
                            
                            ns_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                            auth_name_len = compress_name(ns_name, main_domain_name);
                            for(int j = 0; j < auth_name_len; ++j){
                                return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + 4 + j);
                                *return_authority.name = ns_name[j];
                            }

                            return_authority.type = htons(2); 
                            auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + 4 + auth_name_len);
                            *auth_type_ptr = return_authority.type;

                            return_authority.class = htons(1);
                            auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + 4 + auth_name_len + 2);
                            *auth_class_ptr = return_authority.class;

                            auth_ttl = (u_int32_t)atoi(ns_data[1]);
                            return_authority.ttl = htonl(auth_ttl);
                            auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + 4 + auth_name_len + 4);
                            *auth_ttl_ptr = return_authority.ttl;

                            ns_rdata = (u_int8_t *)calloc(32, sizeof(u_int8_t)); 
                            auth_addr_len = compress_name(ns_rdata, ns_data[4]);

                            return_authority.rdlength = htons(auth_addr_len);
                            auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + 4 + auth_name_len + 8);
                            *auth_rdlength_ptr = return_authority.rdlength;

                            for(int j = 0; j < auth_addr_len; ++j){
                                return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + 4 + auth_name_len + 10 + j);
                                *return_authority.rdata = ns_rdata[j];
                            } 

                            wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + qname_len + 10 + 4 + auth_name_len + 10 + auth_addr_len, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                        }

                    }else{
                        return_header = (Header *)answer_buff;
                        return_header->id = header->id;
                        return_header->qr = 1;
                        return_header->opcode = 0;
                        return_header->aa = 1;
                        return_header->tc = 0;
                        return_header->rd = 1;
                        return_header->ra = 0;
                        return_header->z = 0;
                        return_header->rcode = 0;
                        return_header->qdcount = htons(1);
                        return_header->ancount = htons(0);
                        return_header->nscount = htons(1);
                        return_header->arcount = htons(0);
                        
                        for(int j = 0; j < qname_len; ++j){
                            return_question.qname = (u_int8_t*)(answer_buff + sizeof(Header) + j);
                            *return_question.qname = question.qname[j];
                        }

                        return_question.qtype = htons(1);
                        qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                        *qtype_ptr = return_question.qtype;

                        return_question.qclass = htons(1);
                        qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                        *qclass_ptr = return_question.qclass;

                        soa_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        auth_name_len = compress_name(soa_name, main_domain_name);
                        for(int j = 0; j < auth_name_len; ++j){
                            return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                            *return_authority.name = soa_name[j];
                        }

                        return_authority.type = htons(6);
                        auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len);
                        *auth_type_ptr = return_authority.type;

                        return_authority.class = htons(1);
                        auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 2);
                        *auth_class_ptr = return_authority.class;

                        auth_ttl = (u_int32_t)atoi(soa_data[1]);
                        return_authority.ttl = htonl(auth_ttl);
                        auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 4);
                        *auth_ttl_ptr = return_authority.ttl;     

                        // parse soa return data
                        char **return_soa = (char **)calloc(7, sizeof(char *));
                        for(int j = 0; j < 7; ++j){
                            return_soa[j] = (char *)calloc(32, sizeof(char));
                        }
                        token = strtok(soa_data[4], space_delim);
                        int soa_count = 0;
                        while(token != NULL){
                            strcpy(return_soa[soa_count++], token);
                            token = strtok(NULL, space_delim);
                        }
                        soa_rdata.mname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int mname_len = compress_name(soa_rdata.mname, return_soa[0]);
                        soa_rdata.rname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int rname_len = compress_name(soa_rdata.rname, return_soa[1]);
                        u_int32_t serial = (u_int32_t)atoi(return_soa[2]);
                        soa_rdata.serial = htonl(serial);
                        u_int32_t refresh = (u_int32_t)atoi(return_soa[3]);
                        soa_rdata.refresh = htonl(refresh);
                        u_int32_t retry = (u_int32_t)atoi(return_soa[4]);
                        soa_rdata.retry = htonl(retry);
                        u_int32_t expire = (u_int32_t)atoi(return_soa[5]);
                        soa_rdata.expire = htonl(expire);
                        u_int32_t minimum = (u_int32_t)atoi(return_soa[6]);
                        soa_rdata.minimum = htonl(minimum);

                        return_authority.rdlength = htons(mname_len + rname_len + 20);
                        auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 8);
                        *auth_rdlength_ptr = return_authority.rdlength;

                        for(int j = 0; j < mname_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + j);
                            *return_authority.rdata = soa_rdata.mname[j];
                        }

                        for(int j = 0; j < rname_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + j);
                            *return_authority.rdata = soa_rdata.rname[j];
                        }

                        u_int32_t *serial_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len);
                        *serial_ptr = soa_rdata.serial;
                        u_int32_t *refresh_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 4);
                        *refresh_ptr = soa_rdata.refresh;
                        u_int32_t *retry_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 8);
                        *retry_ptr = soa_rdata.retry;
                        u_int32_t *expire_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 12);
                        *expire_ptr = soa_rdata.expire;
                        u_int32_t *minimum_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 16);
                        *minimum_ptr = soa_rdata.minimum;

                        wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 20, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                    }
                    break;
                case AAAA:
                    zone_file_data = (char *)calloc(zone_file_data_length, sizeof(char));
                    // initialize 2d array to store SOA(authority) resource record
                    soa_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store CNAME(answer) resource record
                    cname_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store AAAA(answer) resource record
                    aaaa_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store NS(authority) resource record
                    ns_data = (char **)calloc(5, sizeof(char *));
                    for(int i = 0; i < 5; ++i){
                        soa_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        cname_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        aaaa_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        ns_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                    }                

                    bool has_type_aaaa = false, has_type_aaaa_cname = false;
                    // retrieve the domain name in the first line of zone-file
                    read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp);
                    read_zone_file_data_length = strlen(zone_file_data);
                    if(zone_file_data[read_zone_file_data_length-1] == '\n')
                        zone_file_data[read_zone_file_data_length-1] = '\0';
                    if(zone_file_data[read_zone_file_data_length-2] == '\r')
                        zone_file_data[read_zone_file_data_length-2] = '\0';
                    
                    main_domain_name = (char *)calloc(32, sizeof(char));
                    strcpy(main_domain_name, zone_file_data);
                        
                    while((read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp)) != -1){
                        read_zone_file_data_length = strlen(zone_file_data);
                        if(zone_file_data[read_zone_file_data_length-1] == '\n')
                            zone_file_data[read_zone_file_data_length-1] = '\0';
                        if(zone_file_data[read_zone_file_data_length-2] == '\r')
                            zone_file_data[read_zone_file_data_length-2] = '\0';
                        // check if there is (@, AAAA) in the string
                        // also store SOA, AAAA and NS resource record in advance
                        char **parsed_zone_file_data = (char **)calloc(5, sizeof(char *));
                        for(int j = 0; j < 5; ++j){
                            parsed_zone_file_data[j] = (char *)calloc(zone_file_data_length, sizeof(char));
                        }
                        int cnt = 0;
                        token = strtok(zone_file_data, comma_delim);
                        while(token != NULL){
                            strcpy(parsed_zone_file_data[cnt++], token);
                            token = strtok(NULL, comma_delim);
                        }
                        // retrieve (@, SOA)
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "SOA") == 0){
                            for(int j = 0; j < 5; ++j){
                                strcpy(soa_data[j], parsed_zone_file_data[j]);
                            }
                        }
                        // retrieve (@, NS) 
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "NS") == 0){
                            for(int j = 0; j < 5; ++j){
                                strcpy(ns_data[j], parsed_zone_file_data[j]);
                            }
                        }

                        if(is_subdomain){
                            // retrieve (subdomain, AAAA)
                            char *cname_subdomain;
                            if(strcmp(parsed_zone_file_data[0], subdomain) == 0 && strcmp(parsed_zone_file_data[3], "AAAA") == 0){
                                has_type_aaaa = true;
                                for(int j = 0; j < 5; ++j){
                                    strcpy(aaaa_data[j], parsed_zone_file_data[j]);        
                                }     
                            }else if(strcmp(parsed_zone_file_data[0], subdomain) == 0 && strcmp(parsed_zone_file_data[3], "CNAME") == 0){
                                has_type_aaaa_cname = true;
                                for(int j = 0; j < 5; ++j){
                                    strcpy(cname_data[j], parsed_zone_file_data[j]);
                                }
                                char *period = strchr(parsed_zone_file_data[4], '.');
                                int len = period - parsed_zone_file_data[4];
                                cname_subdomain = (char *)calloc(zone_file_data_length, sizeof(char));
                                strncpy(cname_subdomain, parsed_zone_file_data[4], len);
                            }
                            if(has_type_aaaa_cname){
                                printf("Cname_subdomain: %s\n", cname_subdomain);
                                if(strcmp(parsed_zone_file_data[0], cname_subdomain) == 0 && strcmp(parsed_zone_file_data[3], "AAAA") == 0){
                                    has_type_aaaa = true;
                                    for(int j = 0; j < 5; ++j){
                                        strcpy(aaaa_data[j], parsed_zone_file_data[j]);
                                    }
                                } 
                            }
                        }else{
                            // retrieve (@, AAAA)
                            if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "AAAA") == 0){
                                has_type_aaaa = true;
                                for(int j = 0; j < 5; ++j){
                                    strcpy(aaaa_data[j], parsed_zone_file_data[j]);
                                }
                            }
                        }
                    }

                    // return answer A and authority NS if found in zone-file
                    if(has_type_aaaa){
                        return_header = (Header *)answer_buff;
                        return_header->id = header->id;
                        return_header->qr = 1;
                        return_header->opcode = 0;
                        return_header->aa = 1;
                        return_header->tc = 0;
                        return_header->rd = 1;
                        return_header->ra = 0;
                        return_header->z = 0;
                        return_header->rcode = 0;
                        return_header->qdcount = htons(1);
                        if(has_type_aaaa_cname){
                            return_header->ancount = htons(2);
                        }else{
                            return_header->ancount = htons(1);
                        }
                        return_header->nscount = htons(1);
                        return_header->arcount = htons(0);

                        for(int j = 0; j < qname_len; ++j){
                            return_question.qname = (u_int8_t *)(answer_buff + sizeof(Header) + j);
                            *return_question.qname = question.qname[j];
                        }

                        return_question.qtype = htons(28);
                        qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                        *qtype_ptr = return_question.qtype;

                        return_question.qclass = htons(1);
                        qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                        *qclass_ptr = return_question.qclass;
                        if(has_type_aaaa_cname){
                            for(int j = 0; j < qname_len; ++j){
                                return_answer.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                                *return_answer.name = question.qname[j];
                            }

                            return_answer.type = htons(5);
                            ans_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len);
                            *ans_type_ptr = return_answer.type;

                            return_answer.class = htons(1);
                            ans_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 2);
                            *ans_class_ptr = return_answer.class;

                            ans_ttl = (u_int32_t)atoi(cname_data[1]);
                            return_answer.ttl = htonl(ans_ttl);
                            ans_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 4);
                            *ans_ttl_ptr = return_answer.ttl;

                            cname_rdata = (u_int8_t *)calloc(32, sizeof(u_int8_t)); 
                            ans_addr_len = compress_name(cname_rdata, cname_data[4]);

                            return_answer.rdlength = htons(ans_addr_len);
                            ans_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 8);
                            *ans_rdlength_ptr = return_answer.rdlength;

                            for(int j = 0; j < ans_addr_len; ++j){
                                return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + j);
                                *return_answer.rdata = cname_rdata[j];
                            } 

                            for(int j = 0; j < ans_addr_len; ++j){
                                return_answer.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + j);
                                *return_answer.name = cname_rdata[j];
                            }

                            return_answer.type = htons(28);
                            ans_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len);
                            *ans_type_ptr = return_answer.type;

                            return_answer.class = htons(1);
                            ans_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 2);
                            *ans_class_ptr = return_answer.class;

                            ans_ttl = (u_int32_t)atoi(aaaa_data[1]);
                            return_answer.ttl = htonl(ans_ttl);
                            ans_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 4);
                            *ans_ttl_ptr = return_answer.ttl;

                            return_answer.rdlength = htons(16);
                            ans_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 8);
                            *ans_rdlength_ptr = return_answer.rdlength;

                            int ret = inet_pton(AF_INET6, aaaa_data[4], (void *)&aaaa_rdata);
                            convert_addr = (u_int8_t *)&aaaa_rdata;
                            for(int j = 0; j < 16; ++j){
                                return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + j);
                                *return_answer.rdata = convert_addr[j];
                            }

                            ns_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                            auth_name_len = compress_name(ns_name, main_domain_name);
                            for(int j = 0; j < auth_name_len; ++j){
                                return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 16 + j);
                                *return_authority.name = ns_name[j];
                            }

                            return_authority.type = htons(2); 
                            auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 16 + auth_name_len);
                            *auth_type_ptr = return_authority.type;

                            return_authority.class = htons(1);
                            auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 16 + auth_name_len + 2);
                            *auth_class_ptr = return_authority.class;

                            auth_ttl = (u_int32_t)atoi(ns_data[1]);
                            return_authority.ttl = htonl(auth_ttl);
                            auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 16 + auth_name_len + 4);
                            *auth_ttl_ptr = return_authority.ttl;

                            ns_rdata = (u_int8_t *)calloc(32, sizeof(u_int8_t)); 
                            auth_addr_len = compress_name(ns_rdata, ns_data[4]);

                            return_authority.rdlength = htons(auth_addr_len);
                            auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 16 + auth_name_len + 8);
                            *auth_rdlength_ptr = return_authority.rdlength;

                            for(int j = 0; j < auth_addr_len; ++j){
                                return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 16 + auth_name_len + 10 + j);
                                *return_authority.rdata = ns_rdata[j];
                            } 

                            wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 16 + auth_name_len + 10 + auth_addr_len, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                        }else{
                            for(int j = 0; j < qname_len; ++j){
                                return_answer.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                                *return_answer.name = question.qname[j];
                            }

                            return_answer.type = htons(28);
                            ans_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len);
                            *ans_type_ptr = return_answer.type;

                            return_answer.class = htons(1);
                            ans_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 2);
                            *ans_class_ptr = return_answer.class;

                            ans_ttl = (u_int32_t)atoi(aaaa_data[1]);
                            return_answer.ttl = htonl(ans_ttl);
                            ans_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 4);
                            *ans_ttl_ptr = return_answer.ttl;

                            return_answer.rdlength = htons(16);
                            ans_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 8);
                            *ans_rdlength_ptr = return_answer.rdlength;

                            int ret = inet_pton(AF_INET6, aaaa_data[4], (void *)&aaaa_rdata);
                            convert_addr = (u_int8_t *)&aaaa_rdata;
                            for(int j = 0; j < 16; ++j){
                                return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + j);
                                *return_answer.rdata = convert_addr[j];
                            }

                            ns_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                            auth_name_len = compress_name(ns_name, main_domain_name);
                            for(int j = 0; j < auth_name_len; ++j){
                                return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + 16 + j);
                                *return_authority.name = ns_name[j];
                            }

                            return_authority.type = htons(2); 
                            auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + 16 + auth_name_len);
                            *auth_type_ptr = return_authority.type;

                            return_authority.class = htons(1);
                            auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + 16 + auth_name_len + 2);
                            *auth_class_ptr = return_authority.class;

                            auth_ttl = (u_int32_t)atoi(ns_data[1]);
                            return_authority.ttl = htonl(auth_ttl);
                            auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + 16 + auth_name_len + 4);
                            *auth_ttl_ptr = return_authority.ttl;

                            ns_rdata = (u_int8_t *)calloc(32, sizeof(u_int8_t)); 
                            auth_addr_len = compress_name(ns_rdata, ns_data[4]);

                            return_authority.rdlength = htons(auth_addr_len);
                            auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + 16 + auth_name_len + 8);
                            *auth_rdlength_ptr = return_authority.rdlength;

                            for(int j = 0; j < auth_addr_len; ++j){
                                return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + 16 + auth_name_len + 10 + j);
                                *return_authority.rdata = ns_rdata[j];
                            } 

                            wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + qname_len + 10 + 16 + auth_name_len + 10 + auth_addr_len, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                        }
                    }else{
                        return_header = (Header *)answer_buff;
                        return_header->id = header->id;
                        return_header->qr = 1;
                        return_header->opcode = 0;
                        return_header->aa = 1;
                        return_header->tc = 0;
                        return_header->rd = 1;
                        return_header->ra = 0;
                        return_header->z = 0;
                        return_header->rcode = 0;
                        return_header->qdcount = htons(1);
                        return_header->ancount = htons(0);
                        return_header->nscount = htons(1);
                        return_header->arcount = htons(0);
                        
                        for(int j = 0; j < qname_len; ++j){
                            return_question.qname = (u_int8_t*)(answer_buff + sizeof(Header) + j);
                            *return_question.qname = question.qname[j];
                        }

                        return_question.qtype = htons(28);
                        qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                        *qtype_ptr = return_question.qtype;

                        return_question.qclass = htons(1);
                        qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                        *qclass_ptr = return_question.qclass;

                        soa_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        auth_name_len = compress_name(soa_name, main_domain_name);
                        for(int j = 0; j < auth_name_len; ++j){
                            return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                            *return_authority.name = soa_name[j];
                        }

                        return_authority.type = htons(6);
                        auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len);
                        *auth_type_ptr = return_authority.type;

                        return_authority.class = htons(1);
                        auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 2);
                        *auth_class_ptr = return_authority.class;

                        auth_ttl = (u_int32_t)atoi(soa_data[1]);
                        return_authority.ttl = htonl(auth_ttl);
                        auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 4);
                        *auth_ttl_ptr = return_authority.ttl;     

                        // parse soa return data
                        char **return_soa = (char **)calloc(7, sizeof(char *));
                        for(int j = 0; j < 7; ++j){
                            return_soa[j] = (char *)calloc(32, sizeof(char));
                        }
                        token = strtok(soa_data[4], space_delim);
                        int soa_count = 0;
                        while(token != NULL){
                            strcpy(return_soa[soa_count++], token);
                            token = strtok(NULL, space_delim);
                        }
                        soa_rdata.mname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int mname_len = compress_name(soa_rdata.mname, return_soa[0]);
                        soa_rdata.rname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int rname_len = compress_name(soa_rdata.rname, return_soa[1]);
                        u_int32_t serial = (u_int32_t)atoi(return_soa[2]);
                        soa_rdata.serial = htonl(serial);
                        u_int32_t refresh = (u_int32_t)atoi(return_soa[3]);
                        soa_rdata.refresh = htonl(refresh);
                        u_int32_t retry = (u_int32_t)atoi(return_soa[4]);
                        soa_rdata.retry = htonl(retry);
                        u_int32_t expire = (u_int32_t)atoi(return_soa[5]);
                        soa_rdata.expire = htonl(expire);
                        u_int32_t minimum = (u_int32_t)atoi(return_soa[6]);
                        soa_rdata.minimum = htonl(minimum);

                        return_authority.rdlength = htons(mname_len + rname_len + 20);
                        auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 8);
                        *auth_rdlength_ptr = return_authority.rdlength;

                        for(int j = 0; j < mname_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + j);
                            *return_authority.rdata = soa_rdata.mname[j];
                        }

                        for(int j = 0; j < rname_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + j);
                            *return_authority.rdata = soa_rdata.rname[j];
                        }

                        u_int32_t *serial_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len);
                        *serial_ptr = soa_rdata.serial;
                        u_int32_t *refresh_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 4);
                        *refresh_ptr = soa_rdata.refresh;
                        u_int32_t *retry_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 8);
                        *retry_ptr = soa_rdata.retry;
                        u_int32_t *expire_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 12);
                        *expire_ptr = soa_rdata.expire;
                        u_int32_t *minimum_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 16);
                        *minimum_ptr = soa_rdata.minimum;

                        wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 20, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                    }
                    break;
                case NS:
                    zone_file_data = (char *)calloc(zone_file_data_length, sizeof(char));
                    // initialize 2d array to store SOA(authority) resource record
                    soa_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store A(answer) resource record
                    a_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store NS(authority) resource record
                    ns_data = (char **)calloc(5, sizeof(char *));

                    for(int i = 0; i < 5; ++i){
                        soa_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        a_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        ns_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                    }     

                    bool has_type_ns = false;
                    // retrieve the domain name in the first line of zone-file
                    read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp);
                    read_zone_file_data_length = strlen(zone_file_data);
                    if(zone_file_data[read_zone_file_data_length-1] == '\n')
                        zone_file_data[read_zone_file_data_length-1] = '\0';
                    if(zone_file_data[read_zone_file_data_length-1] == '\r')
                        zone_file_data[read_zone_file_data_length-2] = '\0';
                    
                    main_domain_name = (char *)calloc(32, sizeof(char));
                    strcpy(main_domain_name, zone_file_data);

                    while((read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp)) != -1){
                        read_zone_file_data_length = strlen(zone_file_data);
                        if(zone_file_data[read_zone_file_data_length-1] == '\n')
                            zone_file_data[read_zone_file_data_length-1] = '\0';
                        if(zone_file_data[read_zone_file_data_length-2] == '\r')
                            zone_file_data[read_zone_file_data_length-2] = '\0';
                        // check if there is (@, NS) in the string
                        // also store A and NS resource record in advance
                        char **parsed_zone_file_data = (char **)calloc(5, sizeof(char *));
                        for(int j = 0; j < 5; ++j){
                            parsed_zone_file_data[j] = (char *)calloc(zone_file_data_length, sizeof(char));
                        }
                        int cnt = 0;
                        token = strtok(zone_file_data, comma_delim);
                        while(token != NULL){
                            strcpy(parsed_zone_file_data[cnt++], token);
                            token = strtok(NULL, comma_delim);
                        }
                        // retrieve (@, SOA)
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "SOA") == 0){
                            for(int j = 0; j < 5; ++j){
                                strcpy(soa_data[j], parsed_zone_file_data[j]);
                            }
                        }
                        // retrieve (@, NS)
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "NS") == 0){
                            has_type_ns = true;
                            for(int j = 0; j < 5; ++j){
                                strcpy(ns_data[j], parsed_zone_file_data[j]);
                            }
                        }
                        // retrieve (dns, A)
                        if(strcmp(parsed_zone_file_data[0], "dns") == 0 && strcmp(parsed_zone_file_data[3], "A") == 0){
                            for(int j = 0; j < 5; ++j){
                                strcpy(a_data[j], parsed_zone_file_data[j]);
                            }
                        }
                    }
                    if(has_type_ns){
                        return_header = (Header *)answer_buff;
                        return_header->id = header->id;
                        return_header->qr = 1;
                        return_header->opcode = 0;
                        return_header->aa = 1;
                        return_header->tc = 0;
                        return_header->rd = 1;
                        return_header->ra = 0;
                        return_header->z = 0;
                        return_header->rcode = 0;
                        return_header->qdcount = htons(1);
                        return_header->ancount = htons(1);
                        return_header->nscount = htons(0);
                        return_header->arcount = htons(1);

                        for(int j = 0; j < qname_len; ++j){
                            return_question.qname = (u_int8_t *)(answer_buff + sizeof(Header) + j);
                            *return_question.qname = question.qname[j];
                        }

                        return_question.qtype = htons(2);
                        qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                        *qtype_ptr = return_question.qtype;

                        return_question.qclass = htons(1);
                        qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                        *qclass_ptr = return_question.qclass;

                        for(int j = 0; j < qname_len; ++j){
                            return_answer.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                            *return_answer.name = question.qname[j];
                        }

                        return_answer.type = htons(2);
                        ans_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len);
                        *ans_type_ptr = return_answer.type;

                        return_answer.class = htons(1);
                        ans_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 2);
                        *ans_class_ptr = return_answer.class;

                        ans_ttl = (u_int32_t)atoi(ns_data[1]);
                        return_answer.ttl = htonl(ans_ttl);
                        ans_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 4);
                        *ans_ttl_ptr = return_answer.ttl;
                        
                        ns_rdata = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        ans_addr_len = compress_name(ns_rdata, ns_data[4]);

                        return_answer.rdlength = htons(ans_addr_len);
                        ans_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 8);
                        *ans_rdlength_ptr = return_answer.rdlength;

                        for(int j = 0; j < ans_addr_len; ++j){
                            return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + j);
                            *return_answer.rdata = ns_rdata[j];
                        }

                        for(int j = 0; j < ans_addr_len; ++j){
                            return_additional.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + j);
                            *return_additional.name = ns_rdata[j];
                        }
                        return_additional.type = htons(1);
                        add_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len);
                        *add_type_ptr = return_additional.type;

                        return_additional.class = htons(1);
                        add_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 2);
                        *add_class_ptr = return_additional.class;

                        add_ttl = (u_int32_t)atoi(a_data[1]);
                        return_additional.ttl = htonl(add_ttl);
                        add_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 4);
                        *add_ttl_ptr = return_additional.ttl;

                        return_additional.rdlength = htons(4);
                        add_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 8);
                        *add_rdlength_ptr = return_additional.rdlength;

                        a_rdata = inet_addr(a_data[4]);
                        convert_addr = (u_int8_t *)&a_rdata;
                        for(int j = 0; j < 4; ++j){
                            return_additional.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + j);
                            *return_additional.rdata = convert_addr[j];
                        }

                        wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + ans_addr_len + 10 + 4, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                        
                    }else{
                        return_header = (Header *)answer_buff;
                        return_header->id = header->id;
                        return_header->qr = 1;
                        return_header->opcode = 0;
                        return_header->aa = 1;
                        return_header->tc = 0;
                        return_header->rd = 1;
                        return_header->ra = 0;
                        return_header->z = 0;
                        return_header->rcode = 0;
                        return_header->qdcount = htons(1);
                        return_header->ancount = htons(0);
                        return_header->nscount = htons(1);
                        return_header->arcount = htons(0);
                        
                        for(int j = 0; j < qname_len; ++j){
                            return_question.qname = (u_int8_t*)(answer_buff + sizeof(Header) + j);
                            *return_question.qname = question.qname[j];
                        }

                        return_question.qtype = htons(2);
                        qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                        *qtype_ptr = return_question.qtype;

                        return_question.qclass = htons(1);
                        qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                        *qclass_ptr = return_question.qclass;

                        soa_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        auth_name_len = compress_name(soa_name, main_domain_name);
                        for(int j = 0; j < auth_name_len; ++j){
                            return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                            *return_authority.name = soa_name[j];
                        }

                        return_authority.type = htons(6);
                        auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len);
                        *auth_type_ptr = return_authority.type;

                        return_authority.class = htons(1);
                        auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 2);
                        *auth_class_ptr = return_authority.class;

                        auth_ttl = (u_int32_t)atoi(soa_data[1]);
                        return_authority.ttl = htonl(auth_ttl);
                        auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 4);
                        *auth_ttl_ptr = return_authority.ttl;     

                        // parse soa return data
                        char **return_soa = (char **)calloc(7, sizeof(char *));
                        for(int j = 0; j < 7; ++j){
                            return_soa[j] = (char *)calloc(32, sizeof(char));
                        }
                        token = strtok(soa_data[4], space_delim);
                        int soa_count = 0;
                        while(token != NULL){
                            strcpy(return_soa[soa_count++], token);
                            token = strtok(NULL, space_delim);
                        }
                        soa_rdata.mname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int mname_len = compress_name(soa_rdata.mname, return_soa[0]);
                        soa_rdata.rname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int rname_len = compress_name(soa_rdata.rname, return_soa[1]);
                        u_int32_t serial = (u_int32_t)atoi(return_soa[2]);
                        soa_rdata.serial = htonl(serial);
                        u_int32_t refresh = (u_int32_t)atoi(return_soa[3]);
                        soa_rdata.refresh = htonl(refresh);
                        u_int32_t retry = (u_int32_t)atoi(return_soa[4]);
                        soa_rdata.retry = htonl(retry);
                        u_int32_t expire = (u_int32_t)atoi(return_soa[5]);
                        soa_rdata.expire = htonl(expire);
                        u_int32_t minimum = (u_int32_t)atoi(return_soa[6]);
                        soa_rdata.minimum = htonl(minimum);

                        return_authority.rdlength = htons(mname_len + rname_len + 20);
                        auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 8);
                        *auth_rdlength_ptr = return_authority.rdlength;

                        for(int j = 0; j < mname_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + j);
                            *return_authority.rdata = soa_rdata.mname[j];
                        }

                        for(int j = 0; j < rname_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + j);
                            *return_authority.rdata = soa_rdata.rname[j];
                        }

                        u_int32_t *serial_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len);
                        *serial_ptr = soa_rdata.serial;
                        u_int32_t *refresh_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 4);
                        *refresh_ptr = soa_rdata.refresh;
                        u_int32_t *retry_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 8);
                        *retry_ptr = soa_rdata.retry;
                        u_int32_t *expire_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 12);
                        *expire_ptr = soa_rdata.expire;
                        u_int32_t *minimum_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 16);
                        *minimum_ptr = soa_rdata.minimum;

                        wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 20, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                    }
                    break;
                case CNAME:                
                    zone_file_data = (char *)calloc(zone_file_data_length, sizeof(char));
                    // initialize 2d array to store SOA(authority) resource record
                    soa_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store CNAME(answer) resource record
                    cname_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store NS(authority) resource record
                    ns_data = (char **)calloc(5, sizeof(char *));
                    for(int i = 0; i < 5; ++i){
                        soa_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        cname_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        ns_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                    }

                    bool has_type_cname = false;
                    // retrieve the domain name in the first line of zone-file
                    read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp);
                    read_zone_file_data_length = strlen(zone_file_data);
                    if(zone_file_data[read_zone_file_data_length-1] == '\n')
                        zone_file_data[read_zone_file_data_length-1] = '\0';
                    if(zone_file_data[read_zone_file_data_length-2] == '\r')
                        zone_file_data[read_zone_file_data_length-2] = '\0';

                    main_domain_name = (char *)calloc(32, sizeof(char));
                    strcpy(main_domain_name, zone_file_data);

                    while((read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp)) != -1){
                        read_zone_file_data_length = strlen(zone_file_data);
                        if(zone_file_data[read_zone_file_data_length-1] == '\n')
                            zone_file_data[read_zone_file_data_length-1] = '\0';
                        if(zone_file_data[read_zone_file_data_length-2] == '\r')
                            zone_file_data[read_zone_file_data_length-2] = '\0';
                        // check if there is (subdomain, CNAME) in the string
                        // also store SOA resource record in advance
                        char **parsed_zone_file_data = (char **)calloc(5, sizeof(char *));
                        for(int j = 0; j < 5; ++j){
                            parsed_zone_file_data[j] = (char *)calloc(zone_file_data_length, sizeof(char));
                        }
                        int cnt = 0;
                        token = strtok(zone_file_data, comma_delim);
                        while(token != NULL){
                            strcpy(parsed_zone_file_data[cnt++], token);
                            token = strtok(NULL, comma_delim);
                        }
                        // (@, SOA)
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "SOA") == 0){
                            for(int j = 0; j < 5; ++j){
                                soa_data[j] = parsed_zone_file_data[j];
                            }
                        }
                        // (@, NS)
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "NS") == 0){
                            for(int j = 0; j < 5; ++j){
                                ns_data[j] = parsed_zone_file_data[j];
                            }
                        }
                        if(is_subdomain){
                            // (subdomain, CNAME)
                            if(strcmp(parsed_zone_file_data[0], subdomain) == 0 && strcmp(parsed_zone_file_data[3], "CNAME") == 0){
                                has_type_cname = true;
                                for(int j = 0; j < 5; ++j){
                                    cname_data[j] = parsed_zone_file_data[j];
                                }
                            }
                        }
                    }

                    if(has_type_cname){
                        return_header = (Header *)answer_buff;
                        return_header->id = header->id;
                        return_header->qr = 1;
                        return_header->opcode = 0;
                        return_header->aa = 1;
                        return_header->tc = 0;
                        return_header->rd = 1;
                        return_header->ra = 0;
                        return_header->z = 0;
                        return_header->rcode = 0;
                        return_header->qdcount = htons(1);
                        return_header->ancount = htons(1);
                        return_header->nscount = htons(1);
                        return_header->arcount = htons(0);

                        for(int j = 0; j < qname_len; ++j){
                            return_question.qname = (u_int8_t*)(answer_buff + sizeof(Header) + j);
                            *return_question.qname = question.qname[j];
                        }

                        return_question.qtype = htons(5);
                        qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                        *qtype_ptr = return_question.qtype;

                        return_question.qclass = htons(1);
                        qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                        *qclass_ptr = return_question.qclass;

                        for(int j = 0; j < qname_len; ++j){
                            return_answer.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                            *return_answer.name = question.qname[j];
                        }

                        return_answer.type = htons(5);
                        ans_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len);
                        *ans_type_ptr = return_answer.type;

                        return_answer.class = htons(1);
                        ans_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 2);
                        *ans_class_ptr = return_answer.class;

                        ans_ttl = (u_int32_t)atoi(cname_data[1]);
                        return_answer.ttl = htonl(ans_ttl);
                        ans_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 4);
                        *ans_ttl_ptr = return_answer.ttl;
                        
                        ns_rdata = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        ans_addr_len = compress_name(ns_rdata, cname_data[4]);

                        return_answer.rdlength = htons(ans_addr_len);
                        ans_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 8);
                        *ans_rdlength_ptr = return_answer.rdlength;

                        for(int j = 0; j < ans_addr_len; ++j){
                            return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + j);
                            *return_answer.rdata = ns_rdata[j];
                        }

                        ns_name = (u_int8_t *)calloc(32, sizeof(char));
                        auth_name_len = compress_name(ns_name, main_domain_name);
                        for(int j = 0; j < qname_len; ++j){
                            return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + j);
                            *return_authority.name = ns_name[j];
                        }

                        return_authority.type = htons(2); 
                        auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + auth_name_len);
                        *auth_type_ptr = return_authority.type;

                        return_authority.class = htons(1);
                        auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + auth_name_len + 2);
                        *auth_class_ptr = return_authority.class;

                        auth_ttl = (u_int32_t)atoi(ns_data[1]);
                        return_authority.ttl = htonl(auth_ttl);
                        auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + auth_name_len + 4);
                        *auth_ttl_ptr = return_authority.ttl;

                        ns_rdata = (u_int8_t *)calloc(32, sizeof(u_int8_t)); 
                        auth_addr_len = compress_name(ns_rdata, ns_data[4]);

                        return_authority.rdlength = htons(auth_addr_len);
                        auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + auth_name_len + 8);
                        *auth_rdlength_ptr = return_authority.rdlength;

                        for(int j = 0; j < auth_addr_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + auth_name_len + 10 + j);
                            *return_authority.rdata = ns_rdata[j];
                        } 
                        wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + auth_name_len + 10 + auth_addr_len, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                    }else{
                        return_header = (Header *)answer_buff;
                        return_header->id = header->id;
                        return_header->qr = 1;
                        return_header->opcode = 0;
                        return_header->aa = 1;
                        return_header->tc = 0;
                        return_header->rd = 1;
                        return_header->ra = 0;
                        return_header->z = 0;
                        return_header->rcode = 0;
                        return_header->qdcount = htons(1);
                        return_header->ancount = htons(0);
                        return_header->nscount = htons(1);
                        return_header->arcount = htons(0);
                        
                        for(int j = 0; j < qname_len; ++j){
                            return_question.qname = (u_int8_t*)(answer_buff + sizeof(Header) + j);
                            *return_question.qname = question.qname[j];
                        }

                        return_question.qtype = htons(5);
                        qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                        *qtype_ptr = return_question.qtype;

                        return_question.qclass = htons(1);
                        qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                        *qclass_ptr = return_question.qclass;

                        soa_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        auth_name_len = compress_name(soa_name, main_domain_name);
                        for(int j = 0; j < auth_name_len; ++j){
                            return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                            *return_authority.name = soa_name[j];
                        }

                        return_authority.type = htons(6);
                        auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len);
                        *auth_type_ptr = return_authority.type;

                        return_authority.class = htons(1);
                        auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 2);
                        *auth_class_ptr = return_authority.class;

                        auth_ttl = (u_int32_t)atoi(soa_data[1]);
                        return_authority.ttl = htonl(auth_ttl);
                        auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 4);
                        *auth_ttl_ptr = return_authority.ttl;     

                        // parse soa return data
                        char **return_soa = (char **)calloc(7, sizeof(char *));
                        for(int j = 0; j < 7; ++j){
                            return_soa[j] = (char *)calloc(32, sizeof(char));
                        }
                        token = strtok(soa_data[4], space_delim);
                        int soa_count = 0;
                        while(token != NULL){
                            strcpy(return_soa[soa_count++], token);
                            token = strtok(NULL, space_delim);
                        }
                        soa_rdata.mname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int mname_len = compress_name(soa_rdata.mname, return_soa[0]);
                        soa_rdata.rname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int rname_len = compress_name(soa_rdata.rname, return_soa[1]);
                        u_int32_t serial = (u_int32_t)atoi(return_soa[2]);
                        soa_rdata.serial = htonl(serial);
                        u_int32_t refresh = (u_int32_t)atoi(return_soa[3]);
                        soa_rdata.refresh = htonl(refresh);
                        u_int32_t retry = (u_int32_t)atoi(return_soa[4]);
                        soa_rdata.retry = htonl(retry);
                        u_int32_t expire = (u_int32_t)atoi(return_soa[5]);
                        soa_rdata.expire = htonl(expire);
                        u_int32_t minimum = (u_int32_t)atoi(return_soa[6]);
                        soa_rdata.minimum = htonl(minimum);

                        return_authority.rdlength = htons(mname_len + rname_len + 20);
                        auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 8);
                        *auth_rdlength_ptr = return_authority.rdlength;

                        for(int j = 0; j < mname_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + j);
                            *return_authority.rdata = soa_rdata.mname[j];
                        }

                        for(int j = 0; j < rname_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + j);
                            *return_authority.rdata = soa_rdata.rname[j];
                        }

                        u_int32_t *serial_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len);
                        *serial_ptr = soa_rdata.serial;
                        u_int32_t *refresh_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 4);
                        *refresh_ptr = soa_rdata.refresh;
                        u_int32_t *retry_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 8);
                        *retry_ptr = soa_rdata.retry;
                        u_int32_t *expire_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 12);
                        *expire_ptr = soa_rdata.expire;
                        u_int32_t *minimum_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 16);
                        *minimum_ptr = soa_rdata.minimum;

                        wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 20, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                    }
                    break;
                case SOA:
                    zone_file_data = (char *)calloc(zone_file_data_length, sizeof(char));
                    // initialize 2d array to store SOA(answer) resource record
                    soa_data = (char **)calloc(5, sizeof(char *));
                    for(int i = 0; i < 5; ++i){
                        soa_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                    }                

                    // retrieve the domain name in the first line of zone-file
                    read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp);
                    read_zone_file_data_length = strlen(zone_file_data);
                    if(zone_file_data[read_zone_file_data_length-1] == '\n')
                        zone_file_data[read_zone_file_data_length-1] = '\0';
                    if(zone_file_data[read_zone_file_data_length-2] == '\r')
                        zone_file_data[read_zone_file_data_length-2] = '\0';
                    
                    main_domain_name = (char *)calloc(32, sizeof(char));
                    strcpy(main_domain_name, zone_file_data);

                    while((read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp)) != -1){
                        read_zone_file_data_length = strlen(zone_file_data);
                        if(zone_file_data[read_zone_file_data_length-1] == '\n')
                            zone_file_data[read_zone_file_data_length-1] = '\0';
                        if(zone_file_data[read_zone_file_data_length-2] == '\r')
                            zone_file_data[read_zone_file_data_length-2] = '\0';
                        // check if there is (@, SOA) in the string
                        // also store SOA resource record in advance
                        char **parsed_zone_file_data = (char **)calloc(5, sizeof(char *));
                        for(int j = 0; j < 5; ++j){
                            parsed_zone_file_data[j] = (char *)calloc(zone_file_data_length, sizeof(char));
                        }
                        int cnt = 0;
                        char *token = strtok(zone_file_data, comma_delim);
                        while(token != NULL){
                            strcpy(parsed_zone_file_data[cnt++], token);
                            token = strtok(NULL, comma_delim);
                        }
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "SOA") == 0){
                            for(int j = 0; j < 5; ++j){
                                soa_data[j] = parsed_zone_file_data[j];
                            }
                        }
                    }

                    return_header = (Header *)answer_buff;
                    return_header->id = header->id;
                    return_header->qr = 1;
                    return_header->opcode = 0;
                    return_header->aa = 1;
                    return_header->tc = 0;
                    return_header->rd = 1;
                    return_header->ra = 0;
                    return_header->z = 0;
                    return_header->rcode = 0;
                    return_header->qdcount = htons(1);
                    return_header->ancount = htons(1);
                    return_header->nscount = htons(0);
                    return_header->arcount = htons(0);
                    
                    for(int j = 0; j < qname_len; ++j){
                        return_question.qname = (u_int8_t*)(answer_buff + sizeof(Header) + j);
                        *return_question.qname = question.qname[j];
                    }

                    return_question.qtype = htons(6);
                    qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                    *qtype_ptr = return_question.qtype;

                    return_question.qclass = htons(1);
                    qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                    *qclass_ptr = return_question.qclass;

                    soa_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                    ans_name_len = compress_name(soa_name, main_domain_name);
                    for(int j = 0; j < ans_name_len; ++j){
                        return_answer.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                        *return_answer.name = soa_name[j];
                    }
                    return_answer.type = htons(6);
                    auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len);
                    *auth_type_ptr = return_answer.type;

                    return_answer.class = htons(1);
                    auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 2);
                    *auth_class_ptr = return_answer.class;

                    auth_ttl = (u_int32_t)atoi(soa_data[1]);
                    return_answer.ttl = htonl(auth_ttl);
                    auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 4);
                    *auth_ttl_ptr = return_answer.ttl;     

                
                    // parse soa return data
                    char **return_soa = (char **)calloc(7, sizeof(char *));
                    for(int j = 0; j < 7; ++j){
                        return_soa[j] = (char *)calloc(32, sizeof(char));
                    }
                    token = strtok(soa_data[4], space_delim);
                    int soa_count = 0;
                    while(token != NULL){
                        strcpy(return_soa[soa_count++], token);
                        token = strtok(NULL, space_delim);
                    }
                    soa_rdata.mname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                    int mname_len = compress_name(soa_rdata.mname, return_soa[0]);
                    soa_rdata.rname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                    int rname_len = compress_name(soa_rdata.rname, return_soa[1]);
                    u_int32_t serial = (u_int32_t)atoi(return_soa[2]);
                    soa_rdata.serial = htonl(serial);
                    u_int32_t refresh = (u_int32_t)atoi(return_soa[3]);
                    soa_rdata.refresh = htonl(refresh);
                    u_int32_t retry = (u_int32_t)atoi(return_soa[4]);
                    soa_rdata.retry = htonl(retry);
                    u_int32_t expire = (u_int32_t)atoi(return_soa[5]);
                    soa_rdata.expire = htonl(expire);
                    u_int32_t minimum = (u_int32_t)atoi(return_soa[6]);
                    soa_rdata.minimum = htonl(minimum);

                    return_answer.rdlength = htons(mname_len + rname_len + 20);
                    auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 8);
                    *auth_rdlength_ptr = return_answer.rdlength;

                    for(int j = 0; j < mname_len; ++j){
                        return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + j);
                        *return_answer.rdata = soa_rdata.mname[j];
                    }

                    for(int j = 0; j < rname_len; ++j){
                        return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + mname_len + j);
                        *return_answer.rdata = soa_rdata.rname[j];
                    }

                    u_int32_t *serial_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + mname_len + rname_len);
                    *serial_ptr = soa_rdata.serial;
                    u_int32_t *refresh_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + mname_len + rname_len + 4);
                    *refresh_ptr = soa_rdata.refresh;
                    u_int32_t *retry_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + mname_len + rname_len + 8);
                    *retry_ptr = soa_rdata.retry;
                    u_int32_t *expire_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + mname_len + rname_len + 12);
                    *expire_ptr = soa_rdata.expire;
                    u_int32_t *minimum_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + mname_len + rname_len + 16);
                    *minimum_ptr = soa_rdata.minimum;

                    wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + ans_name_len + 10 + mname_len + rname_len + 20, 0, (struct sockaddr *)&cli_addr, cli_addr_len);                
                    break;

                case MX: 
                    zone_file_data = (char *)calloc(zone_file_data_length, sizeof(char));
                    // initialize 2d array to store SOA(authority) resource record
                    soa_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store A(answer) resource record
                    a_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store NS(authority) resource record
                    ns_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store MX(Mail exchanger) resource record
                    mx_data = (char **)calloc(5, sizeof(char *));
                    for(int i = 0; i < 5; ++i){
                        soa_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        a_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        ns_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        mx_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                    }
                    bool has_type_mx = false;

                    read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp);
                    read_zone_file_data_length = strlen(zone_file_data);
                    if(zone_file_data[read_zone_file_data_length-1] == '\n')
                        zone_file_data[read_zone_file_data_length-1] = '\0';
                    if(zone_file_data[read_zone_file_data_length-2] == '\r')
                        zone_file_data[read_zone_file_data_length-2] = '\0';

                    main_domain_name = (char *)calloc(32, sizeof(char));
                    strcpy(main_domain_name, zone_file_data);
                    
                    while((read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp)) != -1){
                        read_zone_file_data_length = strlen(zone_file_data);
                        if(zone_file_data[read_zone_file_data_length-1] == '\n')
                            zone_file_data[read_zone_file_data_length-1] = '\0';
                        if(zone_file_data[read_zone_file_data_length-2] == '\r')
                            zone_file_data[read_zone_file_data_length-2] = '\0';
                        // check if there is (@, MX) in the string
                        // also store A, NS and MX resource record in advance
                        char **parsed_zone_file_data = (char **)calloc(5, sizeof(char *));
                        for(int j = 0; j < 5; ++j){
                            parsed_zone_file_data[j] = (char *)calloc(zone_file_data_length, sizeof(char));
                        }
                        int cnt = 0;
                        token = strtok(zone_file_data, comma_delim);
                        while(token != NULL){
                            strcpy(parsed_zone_file_data[cnt++], token);
                            token = strtok(NULL, comma_delim);
                        }
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "SOA") == 0){
                            for(int j = 0; j < 5; ++j){
                                strcpy(soa_data[j], parsed_zone_file_data[j]);
                            }
                        }
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "MX") == 0){
                            has_type_mx = true;
                            for(int j = 0; j < 5; ++j){
                                strcpy(mx_data[j], parsed_zone_file_data[j]);
                            }
                        }
                        if(strcmp(parsed_zone_file_data[0], "mail") == 0 && strcmp(parsed_zone_file_data[3], "A") == 0){
                            for(int j = 0; j < 5; ++j){
                                strcpy(a_data[j], parsed_zone_file_data[j]);
                            }
                        }
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "NS") == 0){
                            for(int j = 0; j < 5; ++j){
                                strcpy(ns_data[j], parsed_zone_file_data[j]);
                            }
                        }
                    }
                    if(has_type_mx){
                        return_header = (Header *)answer_buff;
                        return_header->id = header->id;
                        return_header->qr = 1;
                        return_header->opcode = 0;
                        return_header->aa = 1;
                        return_header->tc = 0;
                        return_header->rd = 1;
                        return_header->ra = 0;
                        return_header->z = 0;
                        return_header->rcode = 0;
                        return_header->qdcount = htons(1);
                        return_header->ancount = htons(1);
                        return_header->nscount = htons(1);
                        return_header->arcount = htons(1);

                        for(int j = 0; j < qname_len; ++j){
                            return_question.qname = (u_int8_t *)(answer_buff + sizeof(Header) + j);
                            *return_question.qname = question.qname[j];
                        }

                        return_question.qtype = htons(15);
                        qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                        *qtype_ptr = return_question.qtype;

                        return_question.qclass = htons(1);
                        qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                        *qclass_ptr = return_question.qclass;

                        mx_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        ans_name_len = compress_name(mx_name, main_domain_name);
                        
                        for(int j = 0; j < ans_name_len; ++j){
                            return_answer.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                            *return_answer.name = mx_name[j];
                        }

                        return_answer.type = htons(15);
                        ans_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len);
                        *ans_type_ptr = return_answer.type;

                        return_answer.class = htons(1);
                        ans_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 2);
                        *ans_class_ptr = return_answer.class;

                        ans_ttl = (u_int32_t)atoi(mx_data[1]);
                        return_answer.ttl = htonl(ans_ttl);
                        ans_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 4);
                        *ans_ttl_ptr = return_answer.ttl;
                        
                        // parse mx return data;
                        char **return_mx = (char **)calloc(2, sizeof(char *));
                        for(int j = 0; j < 2; ++j){
                            return_mx[j] = (char *)calloc(32, sizeof(char));
                        }
                        token = strtok(mx_data[4], space_delim);
                        int mx_count = 0;
                        while(token != NULL){
                            strcpy(return_mx[mx_count++], token);
                            token = strtok(NULL, space_delim);
                        }
                        u_int16_t preference = (u_int16_t)atoi(return_mx[0]);
                        mx_rdata.preference = htons(preference);
                        mx_rdata.exchange = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int exchange_len = compress_name(mx_rdata.exchange, return_mx[1]);

                        return_answer.rdlength = htons(2 + exchange_len);
                        ans_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 8);
                        *ans_rdlength_ptr = return_answer.rdlength;

                        u_int16_t *preference_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10);
                        *preference_ptr = mx_rdata.preference;

                        for(int j = 0; j < exchange_len; ++j){
                            return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + j);
                            *return_answer.rdata = mx_rdata.exchange[j];
                        }

                        ns_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        auth_name_len = compress_name(ns_name, main_domain_name);
                        for(int j = 0; j < auth_name_len; ++j){
                            return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + j);
                            *return_authority.name = ns_name[j];
                        }

                        return_authority.type = htons(2);
                        auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + auth_name_len);
                        *auth_type_ptr = return_authority.type;

                        return_authority.class = htons(1);
                        auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + auth_name_len + 2);
                        *auth_class_ptr = return_authority.class;

                        auth_ttl = (u_int32_t)atoi(ns_data[1]);
                        return_authority.ttl = htonl(auth_ttl);
                        auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + auth_name_len + 4);
                        *auth_ttl_ptr = return_authority.ttl;    

                        ns_rdata = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        auth_addr_len = compress_name(ns_rdata, ns_data[4]);

                        return_authority.rdlength = htons(auth_addr_len);
                        auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + auth_name_len + 8);
                        *auth_rdlength_ptr = return_authority.rdlength;

                        for(int j = 0; j < auth_addr_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + auth_name_len + 10 + j);
                            *return_authority.rdata = ns_rdata[j];
                        } 

                        for(int j = 0; j < exchange_len; ++j){
                            return_additional.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + auth_name_len + 10 + auth_addr_len + j);
                            *return_additional.name = mx_rdata.exchange[j];
                        }

                        return_additional.type = htons(1);
                        add_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + auth_name_len + 10 + auth_addr_len + exchange_len);
                        *add_type_ptr = return_additional.type;

                        return_additional.class = htons(1);
                        add_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + auth_name_len + 10 + auth_addr_len + exchange_len + 2);
                        *add_class_ptr = return_additional.class;

                        add_ttl = (u_int32_t)atoi(a_data[1]);
                        return_additional.ttl = htonl(add_ttl);
                        add_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + auth_name_len + 10 + auth_addr_len + exchange_len + 4);
                        *add_ttl_ptr = return_additional.ttl;

                        return_additional.rdlength = htons(4);
                        add_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + auth_name_len + 10 + auth_addr_len + exchange_len + 8);
                        *add_rdlength_ptr = return_additional.rdlength;

                        a_rdata = inet_addr(a_data[4]);
                        convert_addr = (u_int8_t *)&a_rdata;
                        for(int j = 0; j < 4; ++j){
                            return_additional.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + auth_name_len + 10 + auth_addr_len + exchange_len + 10 + j);
                            *return_additional.rdata = convert_addr[j];
                        }

                        wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + ans_name_len + 10 + 2 + exchange_len + qname_len + 10 + auth_addr_len + exchange_len + 10 + 4, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                    }else{
                        return_header = (Header *)answer_buff;
                        return_header->id = header->id;
                        return_header->qr = 1;
                        return_header->opcode = 0;
                        return_header->aa = 1;
                        return_header->tc = 0;
                        return_header->rd = 1;
                        return_header->ra = 0;
                        return_header->z = 0;
                        return_header->rcode = 0;
                        return_header->qdcount = htons(1);
                        return_header->ancount = htons(0);
                        return_header->nscount = htons(1);
                        return_header->arcount = htons(0);
                        
                        for(int j = 0; j < qname_len; ++j){
                            return_question.qname = (u_int8_t*)(answer_buff + sizeof(Header) + j);
                            *return_question.qname = question.qname[j];
                        }

                        return_question.qtype = htons(15);
                        qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                        *qtype_ptr = return_question.qtype;

                        return_question.qclass = htons(1);
                        qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                        *qclass_ptr = return_question.qclass;

                        soa_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        auth_name_len = compress_name(soa_name, main_domain_name);
                        for(int j = 0; j < auth_name_len; ++j){
                            return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                            *return_authority.name = soa_name[j];
                        }

                        return_authority.type = htons(6);
                        auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len);
                        *auth_type_ptr = return_authority.type;

                        return_authority.class = htons(1);
                        auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 2);
                        *auth_class_ptr = return_authority.class;

                        auth_ttl = (u_int32_t)atoi(soa_data[1]);
                        return_authority.ttl = htonl(auth_ttl);
                        auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 4);
                        *auth_ttl_ptr = return_authority.ttl;     

                        // parse soa return data
                        char **return_soa = (char **)calloc(7, sizeof(char *));
                        for(int j = 0; j < 7; ++j){
                            return_soa[j] = (char *)calloc(32, sizeof(char));
                        }
                        token = strtok(soa_data[4], space_delim);
                        int soa_count = 0;
                        while(token != NULL){
                            strcpy(return_soa[soa_count++], token);
                            token = strtok(NULL, space_delim);
                        }
                        soa_rdata.mname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int mname_len = compress_name(soa_rdata.mname, return_soa[0]);
                        soa_rdata.rname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int rname_len = compress_name(soa_rdata.rname, return_soa[1]);
                        u_int32_t serial = (u_int32_t)atoi(return_soa[2]);
                        soa_rdata.serial = htonl(serial);
                        u_int32_t refresh = (u_int32_t)atoi(return_soa[3]);
                        soa_rdata.refresh = htonl(refresh);
                        u_int32_t retry = (u_int32_t)atoi(return_soa[4]);
                        soa_rdata.retry = htonl(retry);
                        u_int32_t expire = (u_int32_t)atoi(return_soa[5]);
                        soa_rdata.expire = htonl(expire);
                        u_int32_t minimum = (u_int32_t)atoi(return_soa[6]);
                        soa_rdata.minimum = htonl(minimum);

                        return_authority.rdlength = htons(mname_len + rname_len + 20);
                        auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 8);
                        *auth_rdlength_ptr = return_authority.rdlength;

                        for(int j = 0; j < mname_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + j);
                            *return_authority.rdata = soa_rdata.mname[j];
                        }

                        for(int j = 0; j < rname_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + j);
                            *return_authority.rdata = soa_rdata.rname[j];
                        }

                        u_int32_t *serial_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len);
                        *serial_ptr = soa_rdata.serial;
                        u_int32_t *refresh_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 4);
                        *refresh_ptr = soa_rdata.refresh;
                        u_int32_t *retry_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 8);
                        *retry_ptr = soa_rdata.retry;
                        u_int32_t *expire_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 12);
                        *expire_ptr = soa_rdata.expire;
                        u_int32_t *minimum_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 16);
                        *minimum_ptr = soa_rdata.minimum;

                        wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 20, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                    }
                    
                    break;
                case TXT: 
                    zone_file_data = (char *)calloc(zone_file_data_length, sizeof(char));
                    // initialize 2d array to store SOA(authority) resource record
                    soa_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store TXT(answer) resource record
                    txt_data = (char **)calloc(5, sizeof(char *));
                    // initialize 2d array to store NS(authority) resource record
                    ns_data = (char **)calloc(5, sizeof(char *));
                    for(int i = 0; i < 5; ++i){
                        soa_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        txt_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                        ns_data[i] = (char *)calloc(zone_file_data_length, sizeof(char));
                    }

                    bool has_type_txt = false;
                    
                    read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp);
                    read_zone_file_data_length = strlen(zone_file_data);
                    if(zone_file_data[read_zone_file_data_length-1] == '\n')
                        zone_file_data[read_zone_file_data_length-1] = '\0';
                    if(zone_file_data[read_zone_file_data_length-2] == '\r')
                        zone_file_data[read_zone_file_data_length-2] = '\0';
                    
                    main_domain_name = (char *)calloc(32, sizeof(char));
                    strcpy(main_domain_name, zone_file_data);
                    
                    while((read_len = getline(&zone_file_data, &zone_file_data_length, zone_fp)) != -1){
                        read_zone_file_data_length = strlen(zone_file_data);
                        if(zone_file_data[read_zone_file_data_length-1] == '\n')
                            zone_file_data[read_zone_file_data_length-1] = '\0';
                        if(zone_file_data[read_zone_file_data_length-2] == '\r')
                            zone_file_data[read_zone_file_data_length-2] = '\0';
                        // check if there is (@, TXT) in the string
                        // also store TXT resource record in advance
                        char **parsed_zone_file_data = (char **)calloc(5, sizeof(char *));
                        for(int j = 0; j < 5; ++j){
                            parsed_zone_file_data[j] = (char *)calloc(zone_file_data_length, sizeof(char));
                        }
                        int cnt = 0;
                        token = strtok(zone_file_data, comma_delim);
                        while(token != NULL){
                            strcpy(parsed_zone_file_data[cnt++], token);
                            token = strtok(NULL, comma_delim);
                        }
                        // (@, SOA)
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "SOA") == 0){
                            for(int j = 0; j < 5; ++j){
                                strcpy(soa_data[j], parsed_zone_file_data[j]);
                            }
                        }
                        // (@, TXT)
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "TXT") == 0){
                            has_type_txt = true;
                            for(int j = 0; j < 5; ++j){
                                strcpy(txt_data[j], parsed_zone_file_data[j]);
                            }
                        }
                        // (@, NS)
                        if(strcmp(parsed_zone_file_data[0], "@") == 0 && strcmp(parsed_zone_file_data[3], "NS") == 0){
                            for(int j = 0; j < 5; ++j){
                                strcpy(ns_data[j], parsed_zone_file_data[j]);
                            }
                        }
                    }
                    if(has_type_txt){
                        return_header = (Header *)answer_buff;
                        return_header->id = header->id;
                        return_header->qr = 1;
                        return_header->opcode = 0;
                        return_header->aa = 1;
                        return_header->tc = 0;
                        return_header->rd = 1;
                        return_header->ra = 0;
                        return_header->z = 0;
                        return_header->rcode = 0;
                        return_header->qdcount = htons(1);
                        return_header->ancount = htons(1);
                        return_header->nscount = htons(1);
                        return_header->arcount = htons(0);
                        
                        for(int j = 0; j < qname_len; ++j){
                            return_question.qname = (u_int8_t *)(answer_buff + sizeof(Header) + j);
                            *return_question.qname = question.qname[j];
                        }

                        return_question.qtype = htons(16);
                        qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                        *qtype_ptr = return_question.qtype;

                        return_question.qclass = htons(1);
                        qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                        *qclass_ptr = return_question.qclass;

                        for(int j = 0; j < qname_len; ++j){
                            return_answer.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                            *return_answer.name = question.qname[j];
                        }

                        return_answer.type = htons(16);
                        ans_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len);
                        *ans_type_ptr = return_answer.type;

                        return_answer.class = htons(1);
                        ans_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 2);
                        *ans_class_ptr = return_answer.class;

                        ans_ttl = (u_int32_t)atoi(txt_data[1]);
                        return_answer.ttl = htonl(ans_ttl);
                        ans_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 4);
                        *ans_ttl_ptr = return_answer.ttl;
                        
                        txt_rdata = (u_int8_t *)calloc(32, sizeof(char));
                        ans_addr_len = compress_text(txt_rdata, txt_data[4]);
                        
                        return_answer.rdlength = htons(ans_addr_len);
                        ans_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 8);
                        *ans_rdlength_ptr = return_answer.rdlength;

                        for(int j = 0; j < ans_addr_len; ++j){
                            return_answer.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + j);
                            *return_answer.rdata = txt_rdata[j];
                        } 

                        ns_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        auth_name_len = compress_name(ns_name, main_domain_name);
                        for(int j = 0; j < auth_name_len; ++j){
                            return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + j);
                            *return_authority.name = ns_name[j];
                        }

                        return_authority.type = htons(2);
                        auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + auth_name_len);
                        *auth_type_ptr = return_authority.type;

                        return_authority.class = htons(1);
                        auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + auth_name_len + 2);
                        *auth_class_ptr = return_authority.class;

                        auth_ttl = (u_int32_t)atoi(ns_data[1]);
                        return_authority.ttl = htonl(auth_ttl);
                        auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + auth_name_len + 4);
                        *auth_ttl_ptr = return_authority.ttl;
                        
                        ns_rdata = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        auth_addr_len = compress_name(ns_rdata, ns_data[4]);

                        return_authority.rdlength = htons(auth_addr_len);
                        auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + auth_name_len + 8);
                        *auth_rdlength_ptr = return_authority.rdlength;

                        for(int j = 0; j < auth_addr_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + auth_name_len + 10 + j);
                            *return_authority.rdata = ns_rdata[j];
                        } 
                        
                        wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + qname_len + 10 + ans_addr_len + auth_name_len + 10 + auth_addr_len, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                        
                    }else{
                        return_header = (Header *)answer_buff;
                        return_header->id = header->id;
                        return_header->qr = 1;
                        return_header->opcode = 0;
                        return_header->aa = 1;
                        return_header->tc = 0;
                        return_header->rd = 1;
                        return_header->ra = 0;
                        return_header->z = 0;
                        return_header->rcode = 0;
                        return_header->qdcount = htons(1);
                        return_header->ancount = htons(0);
                        return_header->nscount = htons(1);
                        return_header->arcount = htons(0);
                        
                        for(int j = 0; j < qname_len; ++j){
                            return_question.qname = (u_int8_t*)(answer_buff + sizeof(Header) + j);
                            *return_question.qname = question.qname[j];
                        }

                        return_question.qtype = htons(16);
                        qtype_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len);
                        *qtype_ptr = return_question.qtype;

                        return_question.qclass = htons(1);
                        qclass_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 2);
                        *qclass_ptr = return_question.qclass;

                        soa_name = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        auth_name_len = compress_name(soa_name, main_domain_name);
                        for(int j = 0; j < auth_name_len; ++j){
                            return_authority.name = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + j);
                            *return_authority.name = question.qname[j];
                        }

                        return_authority.type = htons(6);
                        auth_type_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len);
                        *auth_type_ptr = return_authority.type;

                        return_authority.class = htons(1);
                        auth_class_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 2);
                        *auth_class_ptr = return_authority.class;

                        auth_ttl = (u_int32_t)atoi(soa_data[1]);
                        return_authority.ttl = htonl(auth_ttl);
                        auth_ttl_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 4);
                        *auth_ttl_ptr = return_authority.ttl;     

                        // parse soa return data
                        char **return_soa = (char **)calloc(7, sizeof(char *));
                        for(int j = 0; j < 7; ++j){
                            return_soa[j] = (char *)calloc(32, sizeof(char));
                        }
                        token = strtok(soa_data[4], space_delim);
                        int soa_count = 0;
                        while(token != NULL){
                            strcpy(return_soa[soa_count++], token);
                            token = strtok(NULL, space_delim);
                        }
                        soa_rdata.mname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int mname_len = compress_name(soa_rdata.mname, return_soa[0]);
                        soa_rdata.rname = (u_int8_t *)calloc(32, sizeof(u_int8_t));
                        int rname_len = compress_name(soa_rdata.rname, return_soa[1]);
                        u_int32_t serial = (u_int32_t)atoi(return_soa[2]);
                        soa_rdata.serial = htonl(serial);
                        u_int32_t refresh = (u_int32_t)atoi(return_soa[3]);
                        soa_rdata.refresh = htonl(refresh);
                        u_int32_t retry = (u_int32_t)atoi(return_soa[4]);
                        soa_rdata.retry = htonl(retry);
                        u_int32_t expire = (u_int32_t)atoi(return_soa[5]);
                        soa_rdata.expire = htonl(expire);
                        u_int32_t minimum = (u_int32_t)atoi(return_soa[6]);
                        soa_rdata.minimum = htonl(minimum);

                        return_authority.rdlength = htons(mname_len + rname_len + 20);
                        auth_rdlength_ptr = (u_int16_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 8);
                        *auth_rdlength_ptr = return_authority.rdlength;

                        for(int j = 0; j < mname_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + j);
                            *return_authority.rdata = soa_rdata.mname[j];
                        }

                        for(int j = 0; j < rname_len; ++j){
                            return_authority.rdata = (u_int8_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + j);
                            *return_authority.rdata = soa_rdata.rname[j];
                        }

                        u_int32_t *serial_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len);
                        *serial_ptr = soa_rdata.serial;
                        u_int32_t *refresh_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 4);
                        *refresh_ptr = soa_rdata.refresh;
                        u_int32_t *retry_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 8);
                        *retry_ptr = soa_rdata.retry;
                        u_int32_t *expire_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 12);
                        *expire_ptr = soa_rdata.expire;
                        u_int32_t *minimum_ptr = (u_int32_t *)(answer_buff + sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 16);
                        *minimum_ptr = soa_rdata.minimum;

                        wr_sz = sendto(sock_fd, answer_buff, sizeof(Header) + qname_len + 4 + auth_name_len + 10 + mname_len + rname_len + 20, 0, (struct sockaddr *)&cli_addr, cli_addr_len);
                    }
                    break;
                default: 
                    printf("Not a available type\n");
                    break;
            }
            fclose(zone_fp);   
        }
    }
    return 0;
}
