#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

static struct nf_hook_ops nfho;
static int port_to_block = 80;

static ssize_t port_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char buf[10];
    int new_port;
    int len = (count < 9) ? count : 9;
    if (copy_from_user(buf, ubuf, len)) return -EFAULT;
    buf[len] = '\0';
    if (kstrtoint(buf, 10, &new_port) == 0) {
        port_to_block = new_port;
        printk(KERN_INFO "Firewall: Rule set to port %d\n", port_to_block);
    }
    return count;
}

static const struct proc_ops p_ops = { .proc_write = port_write };

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP) return NF_ACCEPT;
    tcph = (struct tcphdr *)(skb_network_header(skb) + (iph->ihl * 4));

    if (ntohs(tcph->dest) == port_to_block) {
        printk(KERN_WARNING "FIREWALL: DROPPED port %d to %pI4\n", port_to_block, &iph->saddr);
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static int __init firewall_init(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);
    proc_create("firewall_port", 0666, NULL, &p_ops);
    printk(KERN_INFO "Firewall Module Loaded. Blocking Port: %d\n", port_to_block);

    return 0;
}

static void __exit firewall_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    remove_proc_entry("firewall_port", NULL);
    printk(KERN_INFO "Firewall Module Unloaded.\n");
}

module_init(firewall_init);
module_exit(firewall_exit);
MODULE_LICENSE("GPL");
