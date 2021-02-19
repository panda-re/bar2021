#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

struct node {
    int data;
    struct node* left;
    struct node* right;
};


void spaces (int l) {
    for (int i=0; i<l; i++) printf (" ");
}

void traverse(struct node *n, int l) {
    if (n == NULL) return;
    spaces(l);
    printf ("data=%d\n", n->data);
    if (n->left) {
        spaces(l);
        printf ("traverse left\n");
        traverse(n->left, l+1);
    }
    if (n->right) {
        spaces(l);
        printf ("traverse right\n");
        traverse(n->right, l+1);
    }
}


struct node *get_rand_non_full_node(struct node *n) {
    if (n->right && n->left) {
        if (random() % 2 == 0) 
            return get_rand_non_full_node(n->right);
        else
            return get_rand_non_full_node(n->left);
    }
    return n;
}


int main (int argc, char **argv) {
    srandom(atoi(argv[1]));
    
    struct node *last = NULL;
    struct node *head = (struct node *) malloc(sizeof(struct node));
    head->data = -1;
    head->right = head->left = NULL;

    for (int i=0; i<50; i++) {
        struct node *newn  = (struct node *) malloc(sizeof(struct node));
        newn->data = i;
        newn->left = newn->right = NULL;
        struct node *n = get_rand_non_full_node(head);
        if ((random() % 4) == 0) {
            if (n->left == NULL) 
                n->left = newn;
            else {
                assert (n->right == NULL);
                n->right = newn;
            }
        }
        else {
            if (n->right == NULL) 
                n->right = newn;
            else {
                assert (n->left == NULL);
                n->left = newn;
            }
        }
    }
    traverse(head, 0);
}
