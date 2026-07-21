package analyzer

import (
	"context"
	"log"
	"os/exec"
	"testing"
	"time"
)

func TestExecWithTimeout(t *testing.T) {
	log.Println("start")
	timeout := 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sleep", "10")
	if err := cmd.Start(); err != nil {
		log.Fatalln("error start cmd:", err)
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Println("finish with timeout")
		} else {
			log.Fatalln("error wait cmd:", err)
		}
	}

	//if ctx.Err() == context.DeadlineExceeded {
	//	log.Println("finish with timeout")
	//} else if err != nil {
	//	log.Println("exec failed with:", err)
	//} else {
	//	log.Println("finish")
	//}
	log.Println("finish")
}
