//
//  main.mm
//  crashmon
//
//  Created by ant4g0nist on 01/11/2021.
//

#import "helpers.h"
#import "crashmon.h"
#import <Foundation/Foundation.h>

void help(int argc, const char *argv[])
{
    if(argc<2)
    {
        fprintf(stderr, "Usage: %s [command to run and arguments]\n", argv[0]);
        fprintf(stderr, "Example: %s echo hello world\n", argv[0]);
        exit(RET_ERROR);
    }
}

int main(int argc, const char *argv[],  char * envp[])
{
    context_title("crashmon - ant4g0nist");
    help(argc, argv);

    int exit_status = m1WranglerInit(argc, argv, envp);
    return exit_status;
}