#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/signal.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#define LISTENQ 1000

struct channel
{
    char *channel_name;
    char *topic;
    int num_users;
    int curr_users;
    char **users;
};

int main(int argc, char *argv[])
{

    if (argc < 2)
    {
        printf("usage: ./server <port-number>\n");
        return -1;
    }
    else
    {
        /* Initialize channels */
        struct channel channels[FD_SETSIZE];
        for (int i = 0; i < FD_SETSIZE; ++i)
        {
            channels[i].users = (char **)calloc(FD_SETSIZE, sizeof(char *));
            for (int j = 0; j < FD_SETSIZE; ++j)
            {
                channels[i].users[j] = (char *)calloc(30, sizeof(char));
            }
            channels[i].num_users = 0;
            channels[i].curr_users = 0;
            channels[i].channel_name = "";
            channels[i].topic = "";
        }
        /* Nickname Array */
        char **nicknames = (char **)calloc(FD_SETSIZE, sizeof(char *));
        for (int i = 0; i < FD_SETSIZE; ++i)
        {
            nicknames[i] = (char *)calloc(30, sizeof(char));
        }
        bool getnick[FD_SETSIZE], getuser[FD_SETSIZE];
        struct sockaddr_in servaddr, cliaddr[FD_SETSIZE], temp_cliaddr;
        int nready, client[FD_SETSIZE];
        fd_set rset, allset;
        int sock_fd, listen_fd, conn_fd;
        int num_client = 0, num_channel = 0;

        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd == -1)
        {
            printf("Cannot setup a socket!\n");
            return -1;
        }
        else
        {
            printf("Setup socket successfully!\n");
            bzero(&servaddr, sizeof(servaddr));
            servaddr.sin_family = AF_INET;
            servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
            servaddr.sin_port = htons(atoi(argv[1]));

            if (bind(listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
            {
                printf("Socket bind failed!\n");
                return -1;
            }
            else
            {
                printf("Socket bind successfully!\n");
                if (listen(listen_fd, LISTENQ) != 0)
                {
                    printf("Socket listen failed!\n");
                    return -1;
                }
                else
                {
                    printf("Server listening...\n");
                    int max_fd = listen_fd;
                    int maxi = -1;
                    for (int i = 0; i < FD_SETSIZE; ++i)
                    {
                        client[i] = -1;
                    }
                    FD_ZERO(&allset);
                    FD_SET(listen_fd, &allset);
                    while (true)
                    {
                        rset = allset;
                        nready = select(max_fd + 1, &rset, NULL, NULL, NULL);
                        if (FD_ISSET(listen_fd, &rset))
                        { /* new client connection */
                            socklen_t clilen = sizeof(temp_cliaddr);
                            conn_fd = accept(listen_fd, (struct sockaddr *)&temp_cliaddr, &clilen);
                            if (conn_fd == -1)
                            {
                                printf("Server accpet failed!\n");
                                return -1;
                            }
                            else
                            {
                                int i;
                                for (i = 0; i < FD_SETSIZE; ++i)
                                {
                                    if (client[i] < 0)
                                    {
                                        client[i] = conn_fd; /* save descriptor */
                                        cliaddr[i] = temp_cliaddr;
                                        num_client++;
                                        break;
                                    }
                                }
                                if (i == FD_SETSIZE)
                                {
                                    printf("Too many clients!\n");
                                    return -1;
                                }
                                FD_SET(conn_fd, &allset); /* add new descriptor to set */
                                if (conn_fd > max_fd)
                                    max_fd = conn_fd; /* for select */
                                if (i > maxi)
                                    maxi = i; /* max index in client[] array */
                                if (--nready <= 0)
                                    continue; /* no more readable descriptors */
                            }
                        }

                        for (int i = 0; i <= maxi; ++i)
                        {
                            /* check all clients for data */
                            if ((sock_fd = client[i]) < 0)
                                continue;
                            if (FD_ISSET(sock_fd, &rset))
                            {
                                char *client_str = (char *)calloc(100, sizeof(char));
                                ssize_t rd_sz = read(sock_fd, client_str, 100);

                                if (rd_sz == 0)
                                {
                                    /* connection closed by client */
                                    num_client--;
                                    close(sock_fd);
                                    FD_CLR(sock_fd, &allset);
                                    client[i] = -1;
                                }
                                else
                                {
                                    printf("%s", client_str);
                                    char *cp_client_str = (char *)calloc(100, sizeof(char));

                                    for (int j = 0; j < strlen(client_str); ++j)
                                    {
                                        if (client_str[j] != '\r' && client_str[j] != '\n')
                                            cp_client_str[j] = client_str[j];
                                    }

                                    if (strncmp(cp_client_str, "NICK", 4) != 0 && strncmp(cp_client_str, "USER", 4) != 0 && strncmp(cp_client_str, "PING", 4) != 0 &&
                                        strncmp(cp_client_str, "LIST", 4) != 0 && strncmp(cp_client_str, "JOIN", 4) != 0 && strncmp(cp_client_str, "TOPIC", 5) != 0 &&
                                        strncmp(cp_client_str, "NAMES", 5) != 0 && strncmp(cp_client_str, "PART", 4) != 0 && strncmp(cp_client_str, "USERS", 5) != 0 &&
                                        strncmp(cp_client_str, "PRIVMSG", 7) != 0 && strncmp(cp_client_str, "QUIT", 4) != 0)
                                    {

                                        char *err_unknowncommand = (char *)calloc(100, sizeof(char));
                                        char *pch = strchr(cp_client_str, ' ');
                                        char *cmd = (char *)calloc(40, sizeof(char));
                                        if (pch != NULL)
                                        {
                                            int len = pch - cp_client_str;
                                            strncpy(cmd, cp_client_str, len);
                                        }
                                        else
                                        {
                                            strncpy(cmd, cp_client_str, strlen(cp_client_str));
                                        }
                                        if (nicknames[i] != NULL)
                                        {
                                            sprintf(err_unknowncommand, ":mircd 421 %s %s :Unknown command\n", nicknames[i], cmd);
                                            ssize_t wr_sz = write(sock_fd, err_unknowncommand, strlen(err_unknowncommand));
                                        }
                                        else
                                        {
                                            sprintf(err_unknowncommand, ":mircd 421 %s :Unknown command\n", cmd);
                                            ssize_t wr_sz = write(sock_fd, err_unknowncommand, strlen(err_unknowncommand));
                                        }
                                    }
                                    if (strncmp(cp_client_str, "NICK", 4) == 0)
                                    {
                                        if (strlen(cp_client_str) == 4)
                                        {
                                            char *err_nonicknamegiven = (char *)calloc(100, sizeof(char));
                                            err_nonicknamegiven = ":mircd 431 :No nickname given\n";
                                            ssize_t wr_sz = write(sock_fd, err_nonicknamegiven, strlen(err_nonicknamegiven));
                                        }
                                        else
                                        {
                                            char *temp_nickname = (char *)calloc(30, sizeof(char));
                                            strncpy(temp_nickname, cp_client_str + 5, strlen(cp_client_str + 5));
                                            bool exist = false;
                                            for (int j = 0; j <= maxi; ++j)
                                            {
                                                if (strcmp(nicknames[j], temp_nickname) == 0)
                                                {
                                                    exist = true;
                                                    break;
                                                }
                                            }
                                            if (exist)
                                            {
                                                char *err_nickcollision = (char *)calloc(100, sizeof(char));
                                                sprintf(err_nickcollision, ":mircd 436 %s :Nickname collision KILL\n", temp_nickname);
                                                ssize_t wr_sz = write(sock_fd, err_nickcollision, strlen(err_nickcollision));
                                            }
                                            else
                                            {
                                                getnick[i] = true;
                                                strcpy(nicknames[i], temp_nickname);
                                            }
                                        }
                                    }
                                    else if (strncmp(cp_client_str, "USERS", 5) == 0)
                                    {
                                        char *rpl_usersstart = (char *)calloc(50, sizeof(char));
                                        sprintf(rpl_usersstart, ":mircd 392 %s :USERID   Terminal Host\n", nicknames[i]);
                                        ssize_t wr_sz = write(sock_fd, rpl_usersstart, strlen(rpl_usersstart));

                                        for (int j = 0; j <= maxi; ++j)
                                        {
                                            if (client[j] != -1)
                                            {
                                                char *rpl_users = (char *)calloc(50, sizeof(char));
                                                sprintf(rpl_users, ":mircd 393 %s :%-8s %-9s %-8s\n", nicknames[i], nicknames[j], "-", inet_ntoa(cliaddr[j].sin_addr));
                                                wr_sz = write(sock_fd, rpl_users, strlen(rpl_users));
                                            }
                                        }
                                        char *rpl_endofuser = (char *)calloc(50, sizeof(char));
                                        sprintf(rpl_endofuser, ":mircd 394 %s :End of users\n", nicknames[i]);
                                        wr_sz = write(sock_fd, rpl_endofuser, strlen(rpl_endofuser));
                                    }
                                    else if (strncmp(cp_client_str, "USER", 4) == 0)
                                    {
                                        int cnt_spaces = 0;
                                        for (int j = 0; j < strlen(cp_client_str); ++j)
                                        {
                                            if (cp_client_str[j] == ' ')
                                                cnt_spaces++;
                                        }
                                        if (cnt_spaces != 4)
                                        {
                                            char *err_needmoreparams = (char *)calloc(100, sizeof(char));
                                            sprintf(err_needmoreparams, ":mircd 461 %s USER :Not enough parameters\n", nicknames[i]);
                                            ssize_t wr_sz = write(sock_fd, err_needmoreparams, strlen(err_needmoreparams));
                                        }
                                        else
                                        {
                                            getuser[i] = true;
                                        }
                                    }
                                    else if (strncmp(cp_client_str, "PING", 4) == 0)
                                    {
                                        if (strlen(cp_client_str) == 4)
                                        {
                                            char *err_noorigin = (char *)calloc(100, sizeof(char));
                                            sprintf(err_noorigin, ":mircd 409 %s :No origin specified\n", nicknames[i]);
                                            ssize_t wr_sz = write(sock_fd, err_noorigin, strlen(err_noorigin));
                                        }
                                        else
                                        {
                                            char *server = (char *)calloc(30, sizeof(char));
                                            strncpy(server, cp_client_str + 5, strlen(cp_client_str + 5));
                                            char *pong = (char *)calloc(30, sizeof(char));
                                            sprintf(pong, "PONG %s\n", server);
                                            ssize_t wr_sz = write(sock_fd, pong, strlen(pong));
                                        }
                                    }
                                    else if (strncmp(cp_client_str, "LIST", 4) == 0)
                                    {
                                        char *rpl_liststart = (char *)calloc(100, sizeof(char));
                                        sprintf(rpl_liststart, ":mircd 321 %s Channel :Users  Name\n", nicknames[i]);
                                        ssize_t wr_sz = write(sock_fd, rpl_liststart, strlen(rpl_liststart));

                                        for (int j = 0; j < num_channel; ++j)
                                        {
                                            if (channels[j].num_users != 0)
                                            {
                                                char *rpl_list = (char *)calloc(100, sizeof(char));
                                                sprintf(rpl_list, ":mircd 322 %s %s %d :%s\n", nicknames[i], channels[j].channel_name, channels[j].curr_users, channels[j].topic);
                                                wr_sz = write(sock_fd, rpl_list, strlen(rpl_list));
                                            }
                                        }

                                        char *rpl_listend = (char *)calloc(100, sizeof(char));
                                        sprintf(rpl_listend, ":mircd 323 %s :End of /LIST\n", nicknames[i]);
                                        wr_sz = write(sock_fd, rpl_listend, strlen(rpl_listend));
                                    }
                                    else if (strncmp(cp_client_str, "JOIN", 4) == 0)
                                    {
                                        bool exist = false;
                                        int channel_idx = 0;
                                        char *pch = strchr(cp_client_str, '#');
                                        if (pch != NULL)
                                        {
                                            char *chal_name = (char *)calloc(30, sizeof(char));
                                            int pos = pch - cp_client_str;
                                            strncpy(chal_name, cp_client_str + pos, strlen(cp_client_str + pos));
                                            for (int j = 0; j < num_channel; ++j)
                                            {
                                                if (strcmp(channels[j].channel_name, chal_name) == 0)
                                                {
                                                    exist = true;
                                                    channel_idx = j;
                                                    break;
                                                }
                                            }

                                            for (int j = 0; j <= maxi; ++j)
                                            {
                                                char *join_response = (char *)calloc(50, sizeof(char));
                                                sprintf(join_response, ":%s JOIN %s\n", nicknames[i], chal_name);
                                                ssize_t wr_sz = write(client[j], join_response, strlen(join_response));
                                            }

                                            if (exist)
                                            {
                                                int n_users = channels[channel_idx].num_users;
                                                strcpy(channels[channel_idx].users[n_users], nicknames[i]);
                                                channels[channel_idx].num_users++;
                                                channels[channel_idx].curr_users++;

                                                char **rpl_namereply = (char **)calloc(channels[channel_idx].num_users, sizeof(char *));
                                                char *rpl_notopic = (char *)calloc(100, sizeof(char));
                                                char *rpl_topic = (char *)calloc(100, sizeof(char));
                                                char *rpl_endofnames = (char *)calloc(100, sizeof(char));

                                                if (strcmp(channels[channel_idx].topic, "") == 0)
                                                {
                                                    sprintf(rpl_notopic, ":mircd 331 %s %s :No topic is set\n", nicknames[i], chal_name);
                                                    ssize_t wr_sz = write(sock_fd, rpl_notopic, strlen(rpl_notopic));
                                                }
                                                else
                                                {
                                                    sprintf(rpl_topic, ":mircd 332 %s %s :%s\n", nicknames[i], chal_name, channels[channel_idx].topic);
                                                    ssize_t wr_sz = write(sock_fd, rpl_topic, strlen(rpl_topic));
                                                }

                                                for (int j = 0; j < channels[channel_idx].num_users; ++j)
                                                {
                                                    rpl_namereply[j] = (char *)calloc(50, sizeof(char));
                                                    sprintf(rpl_namereply[j], ":mircd 353 %s %s :%s\n", nicknames[i], chal_name, channels[channel_idx].users[j]);
                                                    ssize_t wr_sz = write(sock_fd, rpl_namereply[j], strlen(rpl_namereply[j]));
                                                }

                                                sprintf(rpl_endofnames, ":mircd 366 %s %s :End of Names List\n", nicknames[i], chal_name);
                                                ssize_t wr_sz = write(sock_fd, rpl_endofnames, strlen(rpl_endofnames));
                                            }
                                            else
                                            {
                                                channels[num_channel].channel_name = (char *)calloc(30, sizeof(char));

                                                strcpy(channels[num_channel].channel_name, chal_name);
                                                strcpy(channels[num_channel].users[0], nicknames[i]);
                                                channels[num_channel].num_users++;
                                                channels[num_channel].curr_users++;

                                                char **rpl_namereply = (char **)calloc(channels[num_channel].num_users, sizeof(char *));
                                                char *rpl_notopic = (char *)calloc(100, sizeof(char));
                                                char *rpl_topic = (char *)calloc(100, sizeof(char));
                                                char *rpl_endofnames = (char *)calloc(100, sizeof(char));

                                                sprintf(rpl_notopic, ":mircd 331 %s %s :No topic is set\n", nicknames[i], chal_name);
                                                ssize_t wr_sz = write(sock_fd, rpl_notopic, strlen(rpl_notopic));

                                                for (int j = 0; j < channels[num_channel].num_users; ++j)
                                                {
                                                    rpl_namereply[j] = (char *)calloc(50, sizeof(char));
                                                    sprintf(rpl_namereply[j], ":mircd 353 %s %s :%s\n", nicknames[i], chal_name, channels[num_channel].users[j]);
                                                    wr_sz = write(sock_fd, rpl_namereply[j], strlen(rpl_namereply[j]));
                                                }

                                                sprintf(rpl_endofnames, ":mircd 366 %s %s :End of Names List\n", nicknames[i], chal_name);
                                                wr_sz = write(sock_fd, rpl_endofnames, strlen(rpl_endofnames));
                                                num_channel++;
                                            }
                                        }
                                        else
                                        {
                                            char *err_needmoreparams = (char *)calloc(100, sizeof(char));
                                            sprintf(err_needmoreparams, ":mircd 461 %s JOIN :Not enough parameters\n", nicknames[i]);
                                            ssize_t wr_sz = write(sock_fd, err_needmoreparams, strlen(err_needmoreparams));
                                        }
                                    }
                                    else if (strncmp(cp_client_str, "TOPIC", 5) == 0)
                                    {
                                        char *chal_pch = strchr(cp_client_str, '#');
                                        if (chal_pch != NULL)
                                        {
                                            int pos = chal_pch - cp_client_str;
                                            char *pch = strchr(cp_client_str, ':');
                                            if (pch != NULL)
                                            {
                                                /* set topic */
                                                int pos2 = pch - cp_client_str + 1;
                                                char *topic = (char *)calloc(50, sizeof(char));
                                                strncpy(topic, cp_client_str + pos2, strlen(cp_client_str + pos2));
                                                char *chal_name = (char *)calloc(50, sizeof(char));
                                                strncpy(chal_name, cp_client_str + pos, pos2 - pos - 2);
                                                bool user_on_channel = false;
                                                for (int j = 0; j < num_channel; ++j)
                                                {
                                                    if (strcmp(channels[j].channel_name, chal_name) == 0)
                                                    {
                                                        for (int k = 0; k < channels[j].num_users; ++k)
                                                        {

                                                            if (strcmp(channels[j].users[k], nicknames[i]) == 0)
                                                            {
                                                                user_on_channel = true;
                                                                break;
                                                            }
                                                        }
                                                        if (user_on_channel)
                                                        {

                                                            channels[j].topic = (char *)calloc(50, sizeof(char));
                                                            strcpy(channels[j].topic, topic);
                                                            char *rpl_topic = (char *)calloc(100, sizeof(char));
                                                            sprintf(rpl_topic, ":mircd 332 %s %s :%s\n", nicknames[i], channels[j].channel_name, channels[j].topic);

                                                            ssize_t wr_sz = write(sock_fd, rpl_topic, strlen(rpl_topic));
                                                        }
                                                        else
                                                        {
                                                            char *err_notonchannel = (char *)calloc(100, sizeof(char));
                                                            sprintf(err_notonchannel, ":mircd 442 %s %s :You are not on that channel\n", nicknames[i], chal_name);
                                                            ssize_t wr_sz = write(sock_fd, err_notonchannel, strlen(err_notonchannel));
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                /* search */
                                                char *chal_name = (char *)calloc(50, sizeof(char));
                                                strncpy(chal_name, cp_client_str + pos, strlen(cp_client_str + pos));
                                                bool user_on_channel = false;
                                                for (int j = 0; j < num_channel; ++j)
                                                {
                                                    if (strcmp(channels[j].channel_name, chal_name) == 0)
                                                    {

                                                        for (int k = 0; k < channels[j].num_users; ++k)
                                                        {
                                                            if (strcmp(channels[j].users[k], nicknames[i]) == 0)
                                                            {
                                                                user_on_channel = true;
                                                                break;
                                                            }
                                                        }
                                                        if (user_on_channel)
                                                        {
                                                            if (strcmp(channels[j].topic, "") != 0)
                                                            {
                                                                char *rpl_topic = (char *)calloc(100, sizeof(char));
                                                                sprintf(rpl_topic, ":mircd 332 %s %s :%s\n", nicknames[i], channels[j].channel_name, channels[j].topic);
                                                                ssize_t wr_sz = write(sock_fd, rpl_topic, strlen(rpl_topic));
                                                            }
                                                            else
                                                            {
                                                                char *rpl_notopic = (char *)calloc(100, sizeof(char));
                                                                sprintf(rpl_notopic, ":mircd 331 %s %s :No topic is set\n", nicknames[i], channels[j].channel_name);
                                                                ssize_t wr_sz = write(sock_fd, rpl_notopic, strlen(rpl_notopic));
                                                            }
                                                        }
                                                        else
                                                        {
                                                            char *err_notonchannel = (char *)calloc(100, sizeof(char));
                                                            sprintf(err_notonchannel, ":mircd 442 %s %s :You are not on that channel\n", nicknames[i], chal_name);
                                                            ssize_t wr_sz = write(sock_fd, err_notonchannel, strlen(err_notonchannel));
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        else
                                        {
                                            char *err_needmoreparams = (char *)calloc(100, sizeof(char));
                                            sprintf(err_needmoreparams, ":mircd 461 %s TOPIC :Not enough parameters\n", nicknames[i]);
                                            ssize_t wr_sz = write(sock_fd, err_needmoreparams, strlen(err_needmoreparams));
                                        }
                                    }
                                    else if (strncmp(cp_client_str, "NAMES", 5) == 0)
                                    {
                                        char *pch = strchr(cp_client_str, '#');
                                        if (pch != NULL)
                                        {
                                            /* specified channel */
                                            char *chal_name = (char *)calloc(50, sizeof(char));
                                            int pos = pch - cp_client_str;
                                            strncpy(chal_name, cp_client_str + pos, strlen(cp_client_str + pos));
                                            for (int j = 0; j < num_channel; ++j)
                                            {
                                                if (strcmp(channels[j].channel_name, chal_name) == 0)
                                                {
                                                    char **rpl_namereply = (char **)calloc(channels[j].num_users, sizeof(char *));
                                                    for (int k = 0; k < channels[j].num_users; ++k)
                                                    {
                                                        rpl_namereply[j] = (char *)calloc(50, sizeof(char));
                                                        sprintf(rpl_namereply[j], ":mircd 353 %s %s :%s\n", nicknames[i], channels[j].channel_name, channels[j].users[k]);
                                                        ssize_t wr_sz = write(sock_fd, rpl_namereply[j], strlen(rpl_namereply[j]));
                                                    }
                                                    char *rpl_endofnames = (char *)calloc(100, sizeof(char));
                                                    sprintf(rpl_endofnames, ":mircd 366 %s %s :End of Names List\n", nicknames[i], channels[j].channel_name);
                                                    ssize_t wr_sz = write(sock_fd, rpl_endofnames, strlen(rpl_endofnames));
                                                    break;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            for (int j = 0; j < num_channel; ++j)
                                            {
                                                if (channels[j].num_users != 0)
                                                {
                                                    char **rpl_namereply = (char **)calloc(channels[j].num_users, sizeof(char *));
                                                    for (int k = 0; k < channels[j].num_users; ++j)
                                                    {
                                                        rpl_namereply[k] = (char *)calloc(50, sizeof(char));
                                                        sprintf(rpl_namereply[k], ":mircd 353 %s %s :%s\n", nicknames[i], channels[j].channel_name, channels[j].users[k]);
                                                        ssize_t wr_sz = write(sock_fd, rpl_namereply[k], strlen(rpl_namereply[k]));
                                                    }
                                                    char *rpl_endofnames = (char *)calloc(100, sizeof(char));
                                                    sprintf(rpl_endofnames, ":mircd 366 %s %s :End of Names List\n", nicknames[i], channels[j].channel_name);
                                                    ssize_t wr_sz = write(sock_fd, rpl_endofnames, strlen(rpl_endofnames));
                                                }
                                            }
                                        }
                                    }
                                    else if (strncmp(cp_client_str, "PART", 4) == 0)
                                    {
                                        char *pch = strchr(cp_client_str, '#');
                                        char *pch2 = strchr(cp_client_str, ':');

                                        if (pch != NULL)
                                        {
                                            int pos = pch - cp_client_str;
                                            char *chal_name = (char *)calloc(30, sizeof(char));
                                            if (pch2 != NULL)
                                            {
                                                int pos2 = pch2 - cp_client_str + 1;
                                                strncpy(chal_name, cp_client_str + pos, pos2 - pos - 2);
                                            }
                                            else
                                            {
                                                strncpy(chal_name, cp_client_str + pos, strlen(cp_client_str + pos));
                                            }
                                            printf("PART %s\n", chal_name);
                                            printf("PART %ld\n", strlen(chal_name));
                                            int channel_idx = 0;
                                            bool exist = false;
                                            bool user_on_channel = false;
                                            for (int j = 0; j < num_channel; ++j)
                                            {
                                                if (strcmp(channels[j].channel_name, chal_name) == 0)
                                                {
                                                    channel_idx = j;
                                                    exist = true;
                                                    for (int k = 0; k < channels[j].num_users; ++k)
                                                    {
                                                        if (strcmp(channels[j].users[k], nicknames[i]) == 0)
                                                        {
                                                            user_on_channel = true;
                                                            break;
                                                        }
                                                    }
                                                    break;
                                                }
                                            }
                                            if (exist && user_on_channel)
                                            {
                                                for (int j = 0; j < channels[channel_idx].num_users; ++j)
                                                {
                                                    if (strcmp(channels[channel_idx].users[j], nicknames[i]) == 0)
                                                    {
                                                        channels[channel_idx].users[j] = "";
                                                        channels[channel_idx].curr_users--;
                                                        break;
                                                    }
                                                }
                                                for (int j = 0; j <= maxi; ++j)
                                                {
                                                    char *part_response = (char *)calloc(50, sizeof(char));
                                                    sprintf(part_response, ":%s PART :%s\n", nicknames[i], channels[channel_idx].channel_name);
                                                    ssize_t wr_sz = write(client[j], part_response, strlen(part_response));
                                                }
                                            }
                                            else if (exist && !user_on_channel)
                                            {
                                                char *err_notonchannel = (char *)calloc(100, sizeof(char));
                                                sprintf(err_notonchannel, ":mircd 442 %s %s :You are not on that channel\n", nicknames[i], chal_name);
                                                ssize_t wr_sz = write(sock_fd, err_notonchannel, strlen(err_notonchannel));
                                            }
                                            else
                                            {
                                                char *err_nosuchchannel = (char *)calloc(100, sizeof(char));
                                                sprintf(err_nosuchchannel, ":mircd 403 %s %s :No such channel\n", nicknames[i], chal_name);
                                                ssize_t wr_sz = write(sock_fd, err_nosuchchannel, strlen(err_nosuchchannel));
                                            }
                                        }
                                        else
                                        {

                                            char *err_needmoreparams = (char *)calloc(100, sizeof(char));
                                            sprintf(err_needmoreparams, ":mircd 461 %s PART :Not enough parameters\n", nicknames[i]);
                                            ssize_t wr_sz = write(sock_fd, err_needmoreparams, strlen(err_needmoreparams));
                                        }
                                    }
                                    else if (strncmp(cp_client_str, "PRIVMSG", 7) == 0)
                                    {
                                        char *pch = strchr(cp_client_str, '#');
                                        char *pch2 = strchr(cp_client_str, ':');
                                        if (pch != NULL && pch2 != NULL)
                                        {
                                            int pos = pch - cp_client_str;
                                            int pos2 = pch2 - cp_client_str + 1;
                                            char *chal_name = (char *)calloc(50, sizeof(char));
                                            char *message = (char *)calloc(50, sizeof(char));
                                            strncpy(chal_name, cp_client_str + pos, pos2 - pos - 2);
                                            strncpy(message, cp_client_str + pos2, strlen(cp_client_str + pos2));
                                            int channel_idx = 0;
                                            bool exist = false;
                                            for (int j = 0; j < num_channel; ++j)
                                            {
                                                if (strcmp(channels[j].channel_name, chal_name) == 0)
                                                {
                                                    channel_idx = j;
                                                    exist = true;
                                                    break;
                                                }
                                            }
                                            if (exist)
                                            {
                                                for (int j = 0; j < channels[channel_idx].num_users; ++j)
                                                {
                                                    for (int k = 0; k <= maxi; ++k)
                                                    {
                                                        if (strcmp(nicknames[k], channels[channel_idx].users[j]) == 0 && strcmp(nicknames[k], nicknames[i]) != 0)
                                                        {
                                                            char *priv_message = (char *)calloc(100, sizeof(char));
                                                            sprintf(priv_message, ":%s PRIVMSG %s :%s\n", nicknames[i], channels[channel_idx].channel_name, message);
                                                            ssize_t wr_sz = write(client[k], priv_message, strlen(priv_message));
                                                        }
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                char *err_nosuchnick = (char *)calloc(100, sizeof(char));
                                                sprintf(err_nosuchnick, ":mircd 401 %s %s :No such nick/channel\n", nicknames[i], chal_name);
                                                ssize_t wr_sz = write(sock_fd, err_nosuchnick, strlen(err_nosuchnick));
                                            }
                                        }
                                        else
                                        {
                                            if (pch == NULL)
                                            {
                                                char *err_norecipient = (char *)calloc(100, sizeof(char));
                                                sprintf(err_norecipient, ":mircd 411 %s :No recipient given (PRIVMSG)\n", nicknames[i]);
                                                ssize_t wr_sz = write(sock_fd, err_norecipient, strlen(err_norecipient));
                                            }
                                            else if (pch2 == NULL)
                                            {
                                                char *err_notexttosend = (char *)calloc(100, sizeof(char));
                                                sprintf(err_notexttosend, ":mircd 412 %s :No text to send\n", nicknames[i]);
                                                ssize_t wr_sz = write(sock_fd, err_notexttosend, strlen(err_notexttosend));
                                            }
                                        }
                                    }
                                    if (getnick[i] && getuser[i])
                                    {
                                        char **motd_messages = (char **)calloc(13, sizeof(char *));
                                        for (int j = 0; j < 13; ++j)
                                        {
                                            motd_messages[j] = (char *)calloc(150, sizeof(char));
                                        }
                                        sprintf(motd_messages[0], ":mircd 001 %s :Welcome to the minimized IRC daemon!\n", nicknames[i]);
                                        sprintf(motd_messages[1], ":mircd 251 %s :There are %d users and 0 invisible on 1 server\n", nicknames[i], num_client);
                                        sprintf(motd_messages[2], ":mircd 375 %s :- mircd Message of the day -\n", nicknames[i]);
                                        sprintf(motd_messages[3], ":mircd 372 %s :-  Hello, World!\n", nicknames[i]);
                                        sprintf(motd_messages[4], ":mircd 372 %s :-               @                    _ \n", nicknames[i]);
                                        sprintf(motd_messages[5], ":mircd 372 %s :-   ____  ___   _   _ _   ____.     | |\n", nicknames[i]);
                                        sprintf(motd_messages[6], ":mircd 372 %s :-  /  _ `'_  \\ | | | '_/ /  __|  ___| |\n", nicknames[i]);
                                        sprintf(motd_messages[7], ":mircd 372 %s :-  | | | | | | | | | |   | |    /  _  |\n", nicknames[i]);
                                        sprintf(motd_messages[8], ":mircd 372 %s :-  | | | | | | | | | |   | |__  | |_| |\n", nicknames[i]);
                                        sprintf(motd_messages[9], ":mircd 372 %s :-  |_| |_| |_| |_| |_|   \\____| \\___,_|\n", nicknames[i]);
                                        sprintf(motd_messages[10], ":mircd 372 %s :-  minimized internet relay chat daemon\n", nicknames[i]);
                                        sprintf(motd_messages[11], ":mircd 372 %s :-\n", nicknames[i]);
                                        sprintf(motd_messages[12], ":mircd 376 %s :End of message of the day\n", nicknames[i]);
                                        for (int j = 0; j < 13; ++j)
                                        {
                                            ssize_t wr_sz = write(sock_fd, motd_messages[j], strlen(motd_messages[j]));
                                        }
                                        getnick[i] = false;
                                        getuser[i] = false;
                                    }
                                }
                                if (--nready <= 0)
                                    break; /* no more readable descriptors */
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}