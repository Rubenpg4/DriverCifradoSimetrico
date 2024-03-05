#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/fs.h>

#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>

#define DRIVER_NAME "DriverCifradoDescifrado"
#define DRIVER_CLASS "DriverCifradoDescifradoClass"
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define NUM_DEVICES 3

static unsigned char keyAES[AES_KEY_SIZE + 1];

static char encrypted_data[256 + AES_BLOCK_SIZE];
static char decrypted_data[256 + AES_BLOCK_SIZE];

static size_t encrypted_data_size = 0;
static size_t decrypted_data_size = 0;

static char *bin_to_hex(const unsigned char *bin, size_t len) {
    char *hex = kmalloc(len * 2 + 1, GFP_KERNEL);
    if (!hex)
        return NULL;

    for (size_t i = 0; i < len; ++i) {
        snprintf(&hex[i * 2], 3, "%02x", bin[i]);
    }

    hex[len * 2] = '\0';
    return hex;
}

static int my_hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len) {
    int byte;
    size_t i, j;

    for (i = 0, j = 0; i < bin_len && hex[j] != '\0' && hex[j + 1] != '\0'; ++i, j += 2) {
        if (sscanf(&hex[j], "%2x", &byte) != 1)
            return -1;
        bin[i] = (unsigned char)byte;
    }

    return i == bin_len ? 0 : -1;
}

static void generate_aes_key(void) {
    static const char allowed_chars[] =
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!@#~$%&/()=?¿¡[]^*{}+-_";
    size_t allowed_chars_len = sizeof(allowed_chars) - 1;

    for (int i = 0; i < AES_KEY_SIZE; i++) {
        unsigned int rand_val;
        get_random_bytes(&rand_val, sizeof(rand_val));
        keyAES[i] = allowed_chars[rand_val % allowed_chars_len];
    }

    keyAES[AES_KEY_SIZE] = '\0';

    pr_info("Clave AES generada: %.*s\n", AES_KEY_SIZE, keyAES);
}

static size_t apply_pkcs7_padding(unsigned char *data, unsigned int data_len, unsigned int buffer_size) {
    if (data_len > buffer_size) {
        pr_err("Error: data_len mayor que buffer_size.\n");
        return 0;
    }

    unsigned int padding_len = AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE);
    if (data_len + padding_len > buffer_size) {
        pr_err("No hay suficiente espacio en el buffer para el padding.\n");
        return 0;
    }

    for (unsigned int i = 0; i < padding_len; i++) {
        data[data_len + i] = padding_len;
    }

    return data_len + padding_len;
}

static int ECCAESencrypt(const u8 *plaintext, unsigned int plen, u8 *ciphertext) {
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    struct crypto_wait wait;
    struct scatterlist sg;
    int ret;

    if (plen <= 0) {
        pr_err("Longitud del texto plano inválida.\n");
        return -EINVAL;
    }

    skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(skcipher)) {
        pr_err("No se pudo asignar skcipher.\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_err("No se pudo asignar la solicitud de skcipher.\n");
        ret = -ENOMEM;
        goto out_free_skcipher;
    }

    crypto_init_wait(&wait);

    if (crypto_skcipher_setkey(skcipher, keyAES, AES_KEY_SIZE)) {
        pr_err("La clave no se pudo configurar.\n");
        ret = -EAGAIN;
        goto out_free_req;
    }

    sg_init_one(&sg, plaintext, plen);
    skcipher_request_set_crypt(req, &sg, &sg, plen, NULL);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);

    pr_info("Iniciando cifrado. Texto plano: %.*s\n", plen, plaintext);
    pr_info("Se va a usar la clave AES: %.*s\n", AES_KEY_SIZE, keyAES);
    ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    if (ret) {
        pr_err("Error durante el cifrado: %d\n", ret);
        goto out_free_req;
    } else {
        encrypted_data_size = plen;
        memcpy(ciphertext, sg_virt(&sg), plen);
    }

    char *hex_encrypted_data = bin_to_hex(sg_virt(&sg), plen);
    if (hex_encrypted_data) {
        strncpy(encrypted_data, hex_encrypted_data, sizeof(encrypted_data) - 1);
        encrypted_data_size = strlen(hex_encrypted_data);
        pr_info("Cifrado exitoso. Datos cifrados en hexadecimal: %s\n", hex_encrypted_data);
        kfree(hex_encrypted_data);
    } else {
        pr_err("Error al convertir los datos cifrados a hexadecimal.\n");
    }

    ret = 0;

    out_free_req:
		skcipher_request_free(req);
    out_free_skcipher:
		crypto_free_skcipher(skcipher);
    return ret;
}

static int ECCAESdesencrypt(const u8 *ciphertext, unsigned int clen, u8 *plaintext) {
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    struct crypto_wait wait;
    struct scatterlist sg;
    int ret = 0;

    if (clen <= 0) {
        pr_err("Longitud del texto plano inválida.\n");
        return -EINVAL;
    }

    skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(skcipher)) {
        pr_err("No se pudo asignar skcipher.\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_err("No se pudo asignar la solicitud de skcipher.\n");
        ret = -ENOMEM;
        goto out_free_skcipher;
    }

    if (crypto_skcipher_setkey(skcipher, keyAES, AES_KEY_SIZE)) {
        pr_err("La clave no se pudo configurar.\n");
        ret = -EAGAIN;
        goto out_free_req;
    }

    unsigned char *binary_data = kmalloc(clen / 2, GFP_KERNEL); 
    if (binary_data) {
        if (my_hex_to_bin(ciphertext, binary_data, clen / 2) == 0) {
            sg_init_one(&sg, binary_data, clen / 2);
            skcipher_request_set_crypt(req, &sg, &sg, clen / 2, NULL);
            skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);

            pr_info("Iniciando descifrado. Texto cifrado: %.*s\n", clen, ciphertext);
            pr_info("Se va a usar la clave AES: %.*s\n", AES_KEY_SIZE, keyAES);
            ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
            if (ret) {
                pr_err("Error durante el descifrado: %d\n", ret);
                goto out_free_req;
            } else {
                decrypted_data_size = clen;
                memcpy(plaintext, sg_virt(&sg), clen);
                pr_info("Descifrado exitoso. Datos descifrados: %.*s\n", decrypted_data_size, plaintext);
            }
        } else {
            pr_err("Error al convertir los datos de hexadecimal a binario.\n");
        }
        kfree(binary_data);
    } else {
        pr_err("Error al asignar memoria para los datos binarios.\n");
    }

    ret = 0;

    out_free_req:
		skcipher_request_free(req);
    out_free_skcipher:
		crypto_free_skcipher(skcipher);
    return ret;
}

static int ECCopen(struct inode *inode, struct file *file) {
    if (iminor(inode) == 0) {
        pr_info("Dispositivo 0 abierto para crear o leer una clave simetrica.\n");
    } else if (iminor(inode) == 1) {
        pr_info("Dispositivo 1 abierto para operaciones de cifrado.\n");
    } else if (iminor(inode) == 2) {
        pr_info("Dispositivo 2 abierto para operaciones de descifrado.\n");
    } else {
        pr_info("Número de dispositivo menor no válido.\n");
        return -ENODEV;
    }
    file->f_pos = 0;
    return 0;
}

static ssize_t ECCread(struct file *file, char __user *buffer, size_t count, loff_t *f_pos) {
    int minor = iminor(file_inode(file));
    size_t data_size = 0;

    if (*f_pos >= encrypted_data_size && minor == 1) {
        return 0;
    }

    if (*f_pos >= decrypted_data_size && minor == 2) {
        return 0;
    }

    switch (minor) {
        case 0:
            generate_aes_key();
            pr_info("Clave AES generada con resultado\n");
            return 0;
        case 1:
            if (encrypted_data_size == 0) {
                pr_info("No hay datos cifrados disponibles.\n");
                return 0;
            }
            data_size = min(count, encrypted_data_size);
            pr_info("Mensaje cifrado: %.*s\n", encrypted_data_size, encrypted_data);
            if (copy_to_user(buffer, encrypted_data, data_size)) {
                return -EFAULT;
            }
            *f_pos += data_size;
            return data_size;

        case 2:
            if (decrypted_data_size == 0) {
                pr_info("No hay datos descifrados disponibles.\n");
                return 0;
            }
            data_size = min(count, decrypted_data_size);
            pr_info("Mensaje descifrado: %.*s\n", decrypted_data_size, decrypted_data);
            if (copy_to_user(buffer, decrypted_data, data_size)) {
                return -EFAULT;
            }
            return data_size;

        default:
            return -ENODEV;
    }
}

static ssize_t ECCwrite(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos) {
    int minor = iminor(file_inode(file));
    char data_buffer[256 + AES_BLOCK_SIZE];
    size_t new_count;
    int result;

    if (copy_from_user(data_buffer, buffer, min((size_t)256, count))) {
        return -EFAULT;
    }


    if (count > 256) {
        pr_err("El mensaje es demasiado largo.\n");
        return -EINVAL;
    }

    if(minor == 1) {
        new_count = apply_pkcs7_padding(data_buffer, count, sizeof(data_buffer));
        if (new_count == 0) {
            pr_err("Falló la aplicación del padding.\n");
            return -EINVAL;
        }
    }


    switch (minor) {
        case 0:
            if (count != AES_KEY_SIZE) {
                pr_err("La longitud de la clave debe ser de %d bytes para AES-256.\n", AES_KEY_SIZE);
                return -EINVAL;
            }

            if (copy_from_user(keyAES, buffer, AES_KEY_SIZE)) {
                return -EFAULT;
            }

            pr_info("Clave AES establecida con exito: %.*s\n", AES_KEY_SIZE, keyAES);
            break;
        case 1:
            result = ECCAESencrypt(data_buffer, new_count, encrypted_data);
            if (encrypted_data_size > 0) {
                pr_info("Mensaje cifrado correctamente. Tamanio de datos cifrados: %zu.\n", encrypted_data_size);
            } else {
                pr_err("Error cifrando el mensaje.\n");
            }
            break;
        case 2:
            result = ECCAESdesencrypt(data_buffer, count, decrypted_data);
            if (decrypted_data_size > 0) {
                pr_info("Mensaje descifrado correctamente. Tamanio de datos descifrados: %zu.\n", decrypted_data_size);
            } else {
                pr_err("Error descifrando el mensaje.\n");
            }
            break;
    }
    return count;
}

static int ECCrelease(struct inode *inode, struct file *file) {
    pr_info("Release");
    return 0;
}

static const struct file_operations ECC_fops = {
    .owner = THIS_MODULE,
    .open = ECCopen,
    .read = ECCread,
    .write = ECCwrite,
    .release = ECCrelease
};

static dev_t major_minor = -1;
static struct cdev ECCcdev[NUM_DEVICES];
static struct class *ECCclass = NULL;

static int __init init_driver(void) {
    int n_device;
    dev_t id_device;
    if (alloc_chrdev_region(&major_minor, 0, NUM_DEVICES, DRIVER_NAME) < 0) {
        pr_err("Major number assignment failed");
        goto error;
    }
    pr_info("%s driver assigned %d major number\n", DRIVER_NAME, MAJOR(major_minor));

    if((ECCclass = class_create(DRIVER_CLASS)) == NULL) {
        pr_err("Class device registering failed");
        goto error;
    }
    pr_info("/sys/class/%s class driver registered\n", DRIVER_CLASS);

    for (n_device = 0; n_device < NUM_DEVICES; n_device++) {
        cdev_init(&ECCcdev[n_device], &ECC_fops);
        id_device = MKDEV(MAJOR(major_minor), MINOR(major_minor) + n_device);

        if(cdev_add(&ECCcdev[n_device], id_device, 1) == -1) {
            pr_err("Device node creation failed");
            goto error;
        }

        if(device_create(ECCclass, NULL, id_device, NULL, DRIVER_NAME "%d", n_device) == NULL) {
            pr_err("Device node creation failed");
            goto error;
        }

        pr_info("Device node /dev/%s%d created\n", DRIVER_NAME, n_device);
    }
    pr_info("ECC driver initialized and loaded\n");
    return 0;

    error:
        if(ECCclass)
            class_destroy(ECCclass);
        if(major_minor != -1)
            unregister_chrdev_region(major_minor, NUM_DEVICES);
        return -1;

}
static void __exit exit_driver(void) {
    int n_device;
    for (n_device = 0; n_device < NUM_DEVICES; n_device++) {
        device_destroy(ECCclass, MKDEV(MAJOR(major_minor), MINOR(major_minor) + n_device));
        cdev_del(&ECCcdev[n_device]);
    }

    class_destroy(ECCclass);
    unregister_chrdev_region(major_minor, NUM_DEVICES);
    pr_info("ECC driver unloaded\n\n\n\n\n\n\n\n\n");
}

MODULE_LICENSE("GPL"); /* Obligatorio */

module_init(init_driver);
module_exit(exit_driver);
