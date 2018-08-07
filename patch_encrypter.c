#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>
#include <strings.h>
#include <stdlib.h>

void	*get_random_key(size_t size)
{
	void	*buffer;
	int		fd;
	int		numberRandomBytesReaded;

	numberRandomBytesReaded = 0;
	if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
		return (NULL);
	if (!(buffer = malloc(size + 1)))
		return (NULL);
	bzero(buffer, size + 1);
	while (numberRandomBytesReaded < 256)
	{
		read(fd, (buffer + numberRandomBytesReaded), size - numberRandomBytesReaded);
		numberRandomBytesReaded = strlen(buffer);
	}
	close(fd);
	return (buffer);
}

void	swap(int *a, int *b)
{
	*a = *a + *b;
	*b = *a - *b;
	*a = *a - *b;
}

void	*_encrypt_zone(unsigned char *zone, size_t size, unsigned char *new_zone, unsigned char *key)
{
	int				tab[256];
	int				i;
	int				j;
	size_t			k;

	if (!zone || !size)
		return (0);
	if (!key)
		key = get_random_key(256);
	i = -1;
	while (++i < 256)
		tab[i] = i;
	i = -1;
	j = 0;
	while (++i < 256)
	{
		j = (j + tab[i] + key[i % 256]) % 256;
		swap(&(tab[i]), &(tab[j]));
	}
	i = 0;
	j = 0;
	k = 0;
	while (k < size)
	{
		i = (i + 1) % 256;
		j = (j + tab[i]) % 256;
		swap(&(tab[i]), &(tab[j]));
		j = (tab[i] + tab[j]) % 256;
		new_zone[k] = zone[k] ^ tab[j];
		k++;
	}
	return (key);
}
