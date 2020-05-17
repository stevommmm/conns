#define _GNU_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h> // PROTO_TCP / PROTO_UDP / sockaddr_in

// Our pcap handle sits out here so we can use signal handlers on it
pcap_t* descr;


void intHandler(int dummy) {
    pcap_breakloop(descr);
}


void format_ip(uint32_t addr, char *hostname, bool resolve) {
    struct hostent *hent;
    struct in_addr ip_addr;
    ip_addr.s_addr = addr;

    sprintf(hostname, "%s", inet_ntoa(ip_addr));

    if (!resolve)
        return;

    hent = gethostbyaddr((char *)&(ip_addr.s_addr), sizeof(ip_addr.s_addr), AF_INET);
    if(hent != NULL) {
        strcpy(hostname, hent->h_name);
    }
}


typedef struct ListAddr {
    struct ListAddr *next;
    uint32_t addr;
    bool internal;
} ListAddr;


typedef struct App {
    struct ListAddr *next;
    bool resolve;
} App;


/** Append an IP to the end of our list, checking for duplicates and
 *  printing the IP if it's a new addition.
 *
 *  \param[in]  app       List head to start from
 *  \param[in]  addr      IP address to be appended
 *  \param[in]  internal  Marker for preloaded host IPs
 */
void list_uniq_append(App *app, uint32_t addr, bool internal) {
    ListAddr *i = app->next;
    ListAddr *item;

    if (app->next == NULL) {
        i = (ListAddr *) app;
        goto alloc;
    }

    // Prevent duplicate entries and move `i` to end of list
    // should probably be sorted list so we dont need to scan it entirely
    while (i->next != NULL) {
        if (i->addr == addr)
            return;
        i = i->next;
    }
    if (i->addr == addr)
        return;

alloc:
    item = malloc(sizeof(ListAddr));
    item->next = NULL;
    item->addr = addr;
    item->internal = internal;

    if (!internal) {
        char hostname[1024];
        format_ip(addr, hostname, app->resolve);
        printf("%s\n", hostname);
    }

    i->next = item;
}


/** Iterate all the interfaces Pcap knows about and insert the IPs to our list
 *  so we can skip over them when we begin adding remote connections.
 *
 *  \param[in]  app      List head to start from
 */
void prepopulate_addrs(App *app) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        fprintf(stderr, "%s\n", errbuf);
        return;
    }
    for(pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        for(pcap_addr_t *a = d->addresses; a != NULL; a = a->next) {
            if(a->addr->sa_family == AF_INET) {
                list_uniq_append(app, ((struct sockaddr_in*)a->addr)->sin_addr.s_addr, true);
            }
        }
    }
    pcap_freealldevs(alldevs);
}


/** Iterate all the interfaces Pcap knows about and insert the IPs to our list
 *  so we can skip over them when we begin adding remote connections.
 *
 *  \param[in]  user  Pointer to a cast App where we'll stick any IPs
 *                    we get notified about.
 */
void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const struct ether_header *eh;
    const struct iphdr *iph;
    App *app = (App *) user;

    eh = (struct ether_header *) packet;
    iph = (struct iphdr *)(packet += 16 /* COOKED SOCK LEN */);

    if (ntohs(eh->ether_type) == ETHERTYPE_IP) {
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
            list_uniq_append(app, iph->saddr, false);
            list_uniq_append(app, iph->daddr, false);
        }
    }
}


int main(int argc, char **argv) {
    App *app;
    ListAddr *listitem;

    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    int opt;

    app = malloc(sizeof(App));
    app->next = NULL;
    app->resolve = false;

    while ((opt = getopt(argc, argv, "r")) != -1) {
        switch (opt) {
        case 'r': app->resolve = true; break;
        default:
            fprintf(stderr, "Usage: %s [-r] [filter]\n", argv[0]);
            free(app);
            return EXIT_FAILURE;
        }
    }

    // Now, open device for sniffing
    descr = pcap_open_live("any", BUFSIZ, 0, 1000, errbuf);
    if(descr == NULL) {
        fprintf(stderr, "pcap_open_live() failed due to [%s]\n", errbuf);
        free(app);
        return EXIT_FAILURE;
    }

    // If an optional filter was supplied compile and load it
    if (optind < argc) {
        // Compile the filter expression
        if(pcap_compile(descr, &fp, argv[optind + 1], 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "\npcap_compile() failed\n");
            pcap_close(descr);
            free(app);
            return EXIT_FAILURE;
        }

        // Set the filter compiled above
        if(pcap_setfilter(descr, &fp) == -1) {
            fprintf(stderr, "\npcap_setfilter() failed\n");
            pcap_close(descr);
            free(app);
            return EXIT_FAILURE;
        }
    } else {
        fprintf(stderr, "Running with no filter, will get everything.\n");
    }

    signal(SIGINT, intHandler);

    prepopulate_addrs(app);

    // Enter into the callback loop, casting and passing our list head
    pcap_loop(descr, -1, callback, (u_char*)app);

    // We wait for ^C to break us out of loop above.
    pcap_close(descr);
    if (fp.bf_len > 0)
        pcap_freecode(&fp);

    while (app->next != NULL) {
        listitem = app->next;
        app->next = listitem->next;
        free(listitem);
    }
    free(app);
    return EXIT_SUCCESS;
}
