package myutils

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
)

type MyNeo4j struct {
	Driver neo4j.DriverWithContext
}

type LayerNotScannedError struct {
	Msg string
}

func (e *LayerNotScannedError) Error() string {
	return fmt.Sprintf("LayerNotScannedError: %s", e.Msg)
}

type LayerNotExistsError struct {
	Msg string
}

func (e *LayerNotExistsError) Error() string {
	return fmt.Sprintf("LayerNotExistsError: %s", e.Msg)
}

func NewNeo4jDriverGlobalConfig() (*MyNeo4j, error) {
	return NewNeo4jDriver(GlobalConfig.Neo4jConfig.Neo4jURI, GlobalConfig.Neo4jConfig.Neo4jUsername,
		GlobalConfig.Neo4jConfig.Neo4jPassword, false)
}

// NewNeo4jDriver 返回一个配置完全的neo4j driver
func NewNeo4jDriver(target, username, password string, initFlag bool) (*MyNeo4j, error) {
	var ret = new(MyNeo4j)
	var err error

	ret.Driver, err = neo4j.NewDriverWithContext(
		target,
		neo4j.BasicAuth(username, password, ""),
	)
	if err != nil {
		return nil, err
	}

	// 验证连接
	err = ret.Driver.VerifyConnectivity(context.TODO())
	if err != nil {
		return nil, err
	}

	// Create indexes to fix the O(N^2) slowness problem in Neo4j.
	// Run unconditionally, since IF NOT EXISTS is safe.
	session := ret.Driver.NewSession(context.TODO(), neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(context.TODO())
	session.ExecuteWrite(context.TODO(), func(tx neo4j.ManagedTransaction) (any, error) {
		// 创建索引：基于节点id
		tx.Run(context.TODO(),
			"CREATE INDEX layer_id_index IF NOT EXISTS FOR (l:Layer) ON (l.id)",
			map[string]any{},
		)

		// 创建索引：基于节点layer-id
		tx.Run(context.TODO(),
			"CREATE INDEX layer_digest_index IF NOT EXISTS FOR (l:Layer) ON (l.digest)",
			map[string]any{},
		)

		// 创建索引：基于节点layer-id
		tx.Run(context.TODO(),
			"CREATE INDEX rawlayer_digest_index IF NOT EXISTS FOR (l:RawLayer) ON (l.digest)",
			map[string]any{},
		)

		return nil, nil
	})

	return ret, err
}

// ImageInsert is the input unit for InsertBatch.
type ImageInsert struct {
	Name  string
	Image *Image
}

// runTx executes a Cypher write query within a transaction and discards results.
func runTx(ctx context.Context, tx neo4j.ManagedTransaction, q string, p map[string]any) error {
	r, err := tx.Run(ctx, q, p)
	if err != nil {
		return err
	}
	_, err = r.Consume(ctx)
	return err
}

// buildLayerParams computes Cypher UNWIND parameters for an image's layer chain.
// Pure function — no I/O. Returns (params, topLayerID, error).
func buildLayerParams(imgName string, image *Image) ([]map[string]any, string, error) {
	params := make([]map[string]any, 0, len(image.Layers))
	preID := ""
	for i, layer := range image.Layers {
		src := layer.Digest
		if src == "" {
			src = layer.Instruction
		}
		dig := Sha256Str(src)
		if dig == "" {
			return nil, "", fmt.Errorf("layer %d of %s: empty digest after SHA256", i, imgName)
		}
		currID := Sha256Str(preID + dig)
		params = append(params, map[string]any{
			"prevID":      preID,
			"currID":      currID,
			"digest":      layer.Digest,
			"size":        layer.Size,
			"instruction": layer.Instruction,
		})
		preID = currID
	}
	return params, preID, nil
}

// insertTx writes one image's layer chain using an existing transaction.
// Uses UNWIND to reduce round-trips to 3 regardless of layer count
// (vs the previous O(N) approach of one tx.Run per layer).
func insertTx(ctx context.Context, tx neo4j.ManagedTransaction, imgName string, params []map[string]any, topID string) error {
	// Round-trip 1: merge all Layer nodes; for layers with a real digest also
	// merge the corresponding RawLayer and the IS_SAME_AS edge.
	if err := runTx(ctx, tx,
		"UNWIND $p AS r "+
			"MERGE (l:Layer {id: r.currID}) "+
			"ON CREATE SET l.digest=r.digest, l.images=[], l.size=r.size, l.instruction=r.instruction "+
			"WITH l, r WHERE r.digest <> '' "+
			"MERGE (rl:RawLayer {digest: r.digest}) "+
			"ON CREATE SET rl.size=r.size, rl.instruction=r.instruction "+
			"MERGE (l)-[:IS_SAME_AS]-(rl)",
		map[string]any{"p": params},
	); err != nil {
		return err
	}

	// Round-trip 2: IS_BASE_OF edges. Requires all Layer nodes to exist (round-trip 1).
	if len(params) > 1 {
		if err := runTx(ctx, tx,
			"UNWIND $p AS r WITH r WHERE r.prevID <> '' "+
				"MATCH (prev:Layer {id: r.prevID}), (curr:Layer {id: r.currID}) "+
				"MERGE (prev)-[:IS_BASE_OF]->(curr)",
			map[string]any{"p": params},
		); err != nil {
			return err
		}
	}

	// Round-trip 3: tag the top layer with the image name.
	return runTx(ctx, tx,
		"MATCH (l:Layer {id: $id}) "+
			"SET l.images = CASE WHEN NOT $name IN l.images THEN l.images + $name ELSE l.images END",
		map[string]any{"id": topID, "name": imgName},
	)
}

// InsertImageToNeo4j inserts a single image's layer chain into Neo4j.
// imgName format: registry/namespace/repository:tag@digest
func (n *MyNeo4j) InsertImageToNeo4j(imgName string, image *Image) error {
	params, topID, err := buildLayerParams(imgName, image)
	if err != nil {
		Logger.Error(err.Error())
		return err
	}
	if len(params) == 0 {
		return nil
	}
	ctx := context.Background()
	session := n.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return nil, insertTx(ctx, tx, imgName, params, topID)
	})
	if err != nil {
		Logger.Error(fmt.Sprintf("InsertImageToNeo4j %s: %v", imgName, err))
	}
	return err
}

// InsertBatch inserts multiple images using a single Neo4j session.
// Each image gets its own transaction (avoids long lock-holding across images),
// but session reuse eliminates per-image connection overhead.
// Returns on the first error; the caller is responsible for retry logic.
func (n *MyNeo4j) InsertBatch(items []ImageInsert) error {
	if len(items) == 0 {
		return nil
	}
	ctx := context.Background()
	session := n.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	for _, item := range items {
		params, topID, err := buildLayerParams(item.Name, item.Image)
		if err != nil {
			Logger.Error(err.Error())
			return err
		}
		if len(params) == 0 {
			continue
		}
		if _, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			return nil, insertTx(ctx, tx, item.Name, params, topID)
		}); err != nil {
			Logger.Error(fmt.Sprintf("InsertBatch %s: %v", item.Name, err))
			return err
		}
	}
	return nil
}

// FindLayerByNodeId 根据node id查找Layer节点
func (neo4jDriver *MyNeo4j) FindLayerByNodeId(nodeId string) (*neo4j.Record, error) {
	ctx := context.Background()
	session := neo4jDriver.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	node, err := session.ExecuteRead(ctx, findLayerByNodeIdFunc(ctx, nodeId))
	if err != nil {
		return nil, err
	}

	return node.(*neo4j.Record), nil
}

// findLayerByNodeIdFunc 返回可用于session.ExecuteRead的func，根据节点id查找Layer节点
func findLayerByNodeIdFunc(ctx context.Context, nodeId string) neo4j.ManagedTransactionWork {

	return func(tx neo4j.ManagedTransaction) (any, error) {
		var result, err = tx.Run(ctx,
			"MATCH (l:Layer {id: $nodeId}) RETURN l",
			map[string]any{"nodeId": nodeId},
		)

		if err != nil {
			return nil, err
		}

		// 必须通过Next消费获取下一个Record
		if result.Next(context.TODO()) {
			return result.Record(), nil
		} else {
			return nil, fmt.Errorf("ExecuteRead got no record of (:Layer {id: %s}) in neo4j", nodeId)
		}
	}
}

// FindSrcImgNameByDigest 根据layer digest找到更有可能是创建该层的源镜像的名称
// 返回的[]string包含由RawLayer相距最近的每个Layer节点下游的第一个包含images属性的节点的全部镜像名称
func (neo4jDriver *MyNeo4j) FindSrcImgNamesByDigest(digest string) ([]string, error) {
	ctx := context.Background()
	session := neo4jDriver.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	layerNodes, err := session.ExecuteRead(ctx, findLayerNodesByRawLayerDigestFunc(ctx, digest))
	if err != nil {
		Logger.Error("Neo4j find Layer nodes IS_SAME_AS RawLayer node with digest", digest, "failed with:", err.Error())
		return nil, err
	}

	ans := []string{}
	for _, layerNode := range layerNodes.([]*neo4j.Record) {
		prop := GetNodeProps(layerNode)
		if nodeId, ok := prop["id"]; ok {
			Logger.Debug("find Layer node id", nodeId.(string), "of layer digest", digest)
			if nodeId == "" {
				Logger.Error("got empty node id for Layer node IS_SAME_AS RawLayer node with digest:", digest)
				continue
			}

			firstImgNames, e := neo4jDriver.FindFirstDownstreamImagesByNodeId(nodeId.(string))
			if e != nil {
				Logger.Error("find first image name list for Layer node id", nodeId.(string), "fail with error:", e.Error())
				continue
			}

			ans = append(ans, firstImgNames...)
		} else {
			Logger.Error(fmt.Sprintf("Layer node have keys: %s", layerNode.Keys))
			continue
		}
	}

	return ans, nil
}

// findLayerNodesByRawLayerDigestFunc 返回可用于session.ExecuteRead的func
// 根据digest找到指定RawLayer关联的全部Layer节点
func findLayerNodesByRawLayerDigestFunc(ctx context.Context, digest string) neo4j.ManagedTransactionWork {

	return func(tx neo4j.ManagedTransaction) (any, error) {
		var result, err = tx.Run(ctx,
			"MATCH (l:Layer)-[:IS_SAME_AS]-(rl:RawLayer {digest: $digest}) "+
				"RETURN l",
			map[string]any{"digest": digest},
		)

		if err != nil {
			return nil, err
		}

		records, err := result.Collect(ctx)

		return records, err
	}
}

// FindUpstreamImagesByNodeId 根据hash(1-2-5)发现Layer节点的上游镜像，组织为[]string并返回
func (neo4jDriver *MyNeo4j) FindUpstreamImagesByNodeId(nodeId string) ([]string, error) {
	result := make([]string, 0)
	imageSet := make(map[string]struct{})

	ctx := context.TODO()
	session := neo4jDriver.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	nodes, err := session.ExecuteRead(ctx, findUpstreamNodesWithImagesByNodeIdFunc(ctx, nodeId))
	if err != nil {
		Logger.Error("Neo4j find upstream Layer nodes with images by node id", nodeId, "failed with:", err.Error())
		return nil, err
	}

	for _, node := range nodes.([]*neo4j.Record) {
		prop := GetNodeProps(node)
		if imagesList, ok := prop["images"]; ok && len(imagesList.([]interface{})) > 0 {
			for _, imageName := range imagesList.([]interface{}) {
				imgNameStr := imageName.(string)
				imageSet[imgNameStr] = struct{}{}
			}
		}
	}

	for k, _ := range imageSet {
		result = append(result, k)
	}

	return result, nil
}

// findUpstreamNodesWithImagesByNodeIdFunc 返回可用于session.ExecuteRead的func，
// 查询返回images属性非空的上游Layer节点according to hash(1-2-5)
func findUpstreamNodesWithImagesByNodeIdFunc(ctx context.Context, nodeId string) neo4j.ManagedTransactionWork {

	return func(tx neo4j.ManagedTransaction) (any, error) {
		var result, err = tx.Run(ctx,
			"MATCH (l:Layer {id: $idHash}) "+
				"WITH l "+
				"MATCH (up:Layer)-[:IS_BASE_OF*]->(l) "+
				"WHERE size(up.images)>0 "+
				"RETURN up",
			map[string]any{"idHash": nodeId},
		)

		if err != nil {
			return nil, err
		}

		records, err := result.Collect(ctx)

		return records, err
	}
}

// FindUpstreamLayerNodesByNodeId 根据hash(1-2-5)发现所有上游Layer节点
func (neo4jDriver *MyNeo4j) FindUpstreamLayerNodesByNodeId(nodeId string) (any, error) {

	ctx := context.TODO()
	session := neo4jDriver.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	upNodes, err := session.ExecuteRead(ctx, findUpstreamNodesByNodeIdFunc(ctx, nodeId))
	if err != nil {
		Logger.Error("Neo4j find upstream Layer nodes by node id", nodeId, "failed with:", err.Error())
		return nil, err
	}

	return upNodes, nil
}

// findUpstreamNodesByNodeIdFunc 返回可用于session.ExecuteRead的func，find upstream Layer Nodes according to hash(1-2-5)
func findUpstreamNodesByNodeIdFunc(ctx context.Context, nodeId string) neo4j.ManagedTransactionWork {

	return func(tx neo4j.ManagedTransaction) (any, error) {
		var result, err = tx.Run(ctx,
			"MATCH (l:Layer {id: $idHash}) "+
				"WITH l "+
				"MATCH (up:Layer)-[:IS_BASE_OF*]->(l) "+
				"RETURN up",
			map[string]any{"idHash": nodeId},
		)

		if err != nil {
			return nil, err
		}

		records, err := result.Collect(ctx)

		return records, err
	}
}

// FindFirstDownstreamImagesByNodeId 根据hash(1-2-5)发现Layer节点的第一批下游镜像，组织为[]string并返回
func (neo4jDriver *MyNeo4j) FindFirstDownstreamImagesByNodeId(nodeId string) ([]string, error) {
	result := make([]string, 0)
	imageSet := make(map[string]struct{})

	ctx := context.TODO()
	session := neo4jDriver.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	nodes, err := session.ExecuteRead(ctx, findFirstDownstreamNodesWithImagesByNodeIdFunc(ctx, nodeId))
	if err != nil {
		Logger.Error("Neo4j find first downstream Layer nodes with images by node id", nodeId, "failed with:", err.Error())
		return nil, err
	}

	for _, node := range nodes.([]*neo4j.Record) {
		prop := GetNodeProps(node)
		if imagesList, ok := prop["images"]; ok && len(imagesList.([]interface{})) > 0 {
			for _, imageName := range imagesList.([]interface{}) {
				strName := imageName.(string)
				imageSet[strName] = struct{}{}
			}
		}
	}

	for k, _ := range imageSet {
		result = append(result, k)
	}

	return result, nil
}

// findFirstDownstreamNodesWithImagesByNodeIdFunc 返回可用于session.ExecuteRead的func，
// 查询返回images属性的第一个非空的下游Layer节点according to hash(1-2-5)
func findFirstDownstreamNodesWithImagesByNodeIdFunc(ctx context.Context, nodeId string) neo4j.ManagedTransactionWork {

	return func(tx neo4j.ManagedTransaction) (any, error) {
		var result, err = tx.Run(ctx,
			"MATCH (l:Layer {id: $idHash}) "+
				"WITH l "+
				"MATCH (l)-[:IS_BASE_OF*]->(down:Layer) "+
				"WHERE size(down.images)>0 "+
				"RETURN down "+
				"LIMIT 1",
			map[string]any{"idHash": nodeId},
		)

		if err != nil {
			return nil, err
		}

		records, err := result.Collect(ctx)

		return records, err
	}
}

// FindDownstreamImagesByNodeId 根据hash(1-2-5)发现Layer节点的下游镜像，组织为[]string并返回
func (neo4jDriver *MyNeo4j) FindDownstreamImagesByNodeId(nodeId string) ([]string, error) {
	result := make([]string, 0)
	imageSet := make(map[string]struct{})

	ctx := context.TODO()
	session := neo4jDriver.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	nodes, err := session.ExecuteRead(ctx, findDownstreamNodesWithImagesByNodeIdFunc(ctx, nodeId))
	if err != nil {
		Logger.Error("Neo4j find downstream Layer nodes with images by node id", nodeId, "failed with:", err.Error())
		return nil, err
	}

	for _, node := range nodes.([]*neo4j.Record) {
		prop := GetNodeProps(node)
		if imagesList, ok := prop["images"]; ok && len(imagesList.([]interface{})) > 0 {
			for _, imageName := range imagesList.([]interface{}) {
				strName := imageName.(string)
				imageSet[strName] = struct{}{}
			}
		}
	}

	for k, _ := range imageSet {
		result = append(result, k)
	}

	return result, nil
}

// findDownstreamNodesWithImagesByNodeIdFunc 返回可用于session.ExecuteRead的func，
// 查询返回images属性非空的下游Layer节点according to hash(1-2-5)
func findDownstreamNodesWithImagesByNodeIdFunc(ctx context.Context, nodeId string) neo4j.ManagedTransactionWork {

	return func(tx neo4j.ManagedTransaction) (any, error) {
		var result, err = tx.Run(ctx,
			"MATCH (l:Layer {id: $idHash}) "+
				"WITH l "+
				"MATCH (l)-[:IS_BASE_OF*]->(down:Layer) "+
				"WHERE size(down.images)>0 "+
				"RETURN down",
			map[string]any{"idHash": nodeId},
		)

		if err != nil {
			return nil, err
		}

		records, err := result.Collect(ctx)

		return records, err
	}
}

// FindDownstreamLayerNodesByNodeId 根据hash(1-2-5)发现所有下游Layer节点
func (neo4jDriver *MyNeo4j) FindDownstreamLayerNodesByNodeId(nodeId string) (any, error) {

	ctx := context.TODO()
	session := neo4jDriver.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	nodes, err := session.ExecuteRead(ctx, findDownstreamNodesByNodeIdFunc(ctx, nodeId))
	if err != nil {
		Logger.Error("Neo4j find downstream Layer nodes by node id", nodeId, "failed with:", err.Error())
		return nil, err
	}

	return nodes, nil
}

// findDownstreamNodesByNodeIdFunc 返回可用于session.ExecuteRead的func，find downstream Layer Nodes according to hash(1-2-5)
func findDownstreamNodesByNodeIdFunc(ctx context.Context, nodeId string) neo4j.ManagedTransactionWork {

	return func(tx neo4j.ManagedTransaction) (any, error) {
		var result, err = tx.Run(ctx,
			"MATCH (l:Layer {id: $idHash}) "+
				"WITH l "+
				"MATCH (l)-[:IS_BASE_OF*]->(down:Layer) "+
				"RETURN down",
			map[string]any{"idHash": nodeId},
		)

		if err != nil {
			return nil, err
		}

		records, err := result.Collect(ctx)

		return records, err
	}
}

// GetNodeProps 解析neo4j driver ExecuteRead返回*neo4j.Record节点属性
func GetNodeProps(n *neo4j.Record) map[string]any {
	keys := n.Keys
	if len(keys) == 1 {
		prop, _ := n.Get(keys[0])
		return prop.(dbtype.Node).Props
	}

	return nil
}

// DropNodesAndRelationshipsFromNeo4j 将neo4j数据库清空
func (neo4jDriver *MyNeo4j) DropNodesAndRelationshipsFromNeo4j() {
	ctx := context.TODO()
	session := neo4jDriver.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	session.ExecuteWrite(ctx, func(transaction neo4j.ManagedTransaction) (any, error) {
		transaction.Run(ctx,
			"MATCH (i)-[j]->(k) DELETE i,j,k",
			map[string]any{})
		transaction.Run(ctx,
			"MATCH (n) DELETE n",
			map[string]any{})

		return nil, nil
	})
}

func CalculateImageNodeId(img *Image) string {
	preId := ""

	for _, layer := range img.Layers {
		dig := ""

		if layer.Digest != "" {
			dig = Sha256Str(layer.Digest)
		} else {
			dig = Sha256Str(layer.Instruction)
		}
		if dig == "" {
			break
		}

		preId = Sha256Str(preId + dig)
	}

	return preId
}

func IsLayerNotScannedError(err error) bool {
	_, is := err.(*LayerNotScannedError)
	return is
}
