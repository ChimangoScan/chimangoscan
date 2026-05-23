package myutils

import (
	"fmt"
	"testing"
)

func TestInit(t *testing.T) {
	fmt.Println(GlobalConfig)
	fmt.Println("MongoDB connection:", GlobalDBClient.MongoFlag)
	fmt.Println("Neo4j connection:", GlobalDBClient.Neo4jFlag)
	fmt.Println(GlobalDBClient.Neo4j.Driver.Target())
}
