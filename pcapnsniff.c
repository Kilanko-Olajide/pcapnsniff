#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

// Maximum bytes to capture per packet
#define NUM_PACKETS 3       


void dump(const unsigned char *packet, int packet_length) {
    int i, j;

    for (i = 0; i < packet_length; i++) {
        printf("%02x ", (unsigned char) (packet[i]));

        if (((i % 16) == 15) || (i ==(packet_length-1) )) {
            printf("    |   ");
            for (j = i-(i%16);j<(i+1); j++) {
                if ((unsigned char) packet[j] > 31 && (unsigned char) packet[j] < 127) {
                    printf("%c ", (unsigned char) packet[j]);
                } 
                else 
                    printf(".");
            }
            printf("\n");
        }
    }
}

int main(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;
    pcap_t *handle;
    const unsigned char  *packet;
    struct pcap_pkthdr header;
    pcap_if_t *alldevs, *d;
    int i, j;


    // Retrieve the device list using pcap_findalldevs (pcap_lookupdev is deprecated)
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    // Print the list of available devices
    printf("Available devices:\n");
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)", d->description);
        printf("\n");
    }

    if (i == 0) {
        printf("\nNo interfaces found!\n");
        return EXIT_FAILURE;
    }

    int device_num;

    // Prompt for the device to sniff on
    printf("What device do you want to sniff on\n");
    scanf("%d", &device_num);


    for (d = alldevs, i = 1; i < device_num; d = d->next, i++);
    printf("Sniffing on device: %s\n", d->name);

    // Enable promiscuous mode
    handle = pcap_open_live(device, 1024, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Unable to open device %s: %s\n", device, errbuf);
        exit(EXIT_FAILURE);
    }


    for (int i = 0; i < NUM_PACKETS; i++) {
        packet = pcap_next(handle, &header);
        if (packet == NULL) {
            printf("No packet captured.\n");
            continue;
        }
        printf("\nPacket %d captured:\n", i + 1);
        printf("Packet length: %d bytes\n", header.len);
        dump(packet, header.len);
    }
    printf("\n");
    // Close the capture handle.
    pcap_close(handle);
}
