package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ChimangoScan/DITector/myutils"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Target struct {
	Image        string   `json:"image"`
	Namespace    string   `json:"namespace"`
	Repository   string   `json:"repository"`
	Tag          string   `json:"tag"`
	Digest       string   `json:"digest"`
	Pulls        int64    `json:"pull_count"`
	Stars        int64    `json:"star_count"`
	Weight       int      `json:"dependency_weight"`
	Expose       []string `json:"exposed_ports"`
	OS           string   `json:"os"`
	Arch         string   `json:"architecture"`
	Size         int64    `json:"size_bytes"`
	LastUpdate   string   `json:"last_updated"`
	Description  string   `json:"description"`
	Instructions []string `json:"instructions"`
}

func cleanPorts(raw string) []string {
	p := strings.TrimPrefix(raw, "EXPOSE ")
	p = strings.TrimSpace(p)
	var ports []string
	if strings.HasPrefix(p, "map[") {
		p = strings.TrimPrefix(strings.TrimSuffix(p, "]"), "map[")
		for _, part := range strings.Split(p, " ") {
			port := strings.Split(part, ":")[0]
			if port != "" { ports = append(ports, port) }
		}
	} else {
		p = strings.NewReplacer("[", "", "]", "").Replace(p)
		for _, pt := range strings.Split(p, " ") {
			if pt != "" { ports = append(ports, pt) }
		}
	}
	return ports
}

func main() {
	myutils.LoadConfigFromFile("config.yaml", 2)
	db, err := myutils.NewMongoGlobalConfig()
	if err != nil { return }
	defer db.Client.Disconnect(context.Background())

	if !myutils.GlobalDBClient.Neo4jFlag { return }

	ctx := context.Background()
	sess := myutils.GlobalDBClient.Neo4j.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer sess.Close(ctx)

	const cypher = `
		MATCH (exp:Layer) WHERE exp.instruction STARTS WITH "EXPOSE"
		MATCH (exp)-[:IS_BASE_OF*0..]->(leaf:Layer) WHERE size(leaf.images) > 0
		RETURN leaf.id as id, leaf.images as refs, collect(distinct exp.instruction) as ports`

	res, err := sess.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		r, e := tx.Run(ctx, cypher, nil)
		if e != nil { return nil, e }
		return r.Collect(ctx)
	})
	if err != nil { return }

	var dataset []Target
	for _, rec := range res.([]*neo4j.Record) {
		idVal, _ := rec.Get("id")
		refsVal, _ := rec.Get("refs")
		portsVal, _ := rec.Get("ports")

		dw, _ := myutils.GlobalDBClient.Neo4j.FindDownstreamImagesByNodeId(idVal.(string))
		
		var expose []string
		for _, p := range portsVal.([]any) {
			expose = append(expose, cleanPorts(p.(string))...)
		}

		for _, r := range refsVal.([]any) {
			ref := r.(string)
			if ref == "" || strings.HasPrefix(ref, ":") || strings.HasPrefix(ref, "@") { continue }
			_, ns, repo, tag, digest := myutils.DivideImageName(ref)
			if repo == "" { continue }

			rDoc, _ := db.FindRepositoryByName(ns, repo)
			tDoc, _ := db.FindTagByName(ns, repo, tag)
			iDoc, _ := db.FindImageByDigest(digest)

			display := fmt.Sprintf("%s/%s:%s", ns, repo, tag)
			if ns == "library" { display = fmt.Sprintf("%s:%s", repo, tag) }

			t := Target{
				Image: display, Namespace: ns, Repository: repo, Tag: tag, Digest: digest,
				Weight: len(dw), Expose: expose, OS: "linux", Arch: "amd64", Instructions: []string{},
			}

			if iDoc != nil {
				t.OS = iDoc.OS; t.Arch = iDoc.Architecture; t.Size = iDoc.Size
				for _, l := range iDoc.Layers {
					if l.Instruction != "" { t.Instructions = append(t.Instructions, l.Instruction) }
				}
			}
			if rDoc != nil {
				t.Pulls = rDoc.PullCount; t.Stars = rDoc.StarCount; t.Description = rDoc.Description
			}
			if tDoc != nil { t.LastUpdate = tDoc.LastUpdated }
			dataset = append(dataset, t)
		}
	}

	sort.Slice(dataset, func(i, j int) bool {
		if dataset[i].Weight != dataset[j].Weight { return dataset[i].Weight > dataset[j].Weight }
		return dataset[i].Pulls > dataset[j].Pulls
	})

	f, _ := os.Create("network_services_final.jsonl")
	enc := json.NewEncoder(f)
	for _, item := range dataset { enc.Encode(item) }
	f.Close()
	fmt.Printf("Final extraction complete: %d records.\n", len(dataset))
}
