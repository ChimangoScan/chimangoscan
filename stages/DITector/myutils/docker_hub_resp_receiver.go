package myutils

// Docker Hub API返回的直接结果格式

type Repository struct {
	User              string `json:"user" bson:"user"`
	Name              string `json:"name" bson:"name"`
	Namespace         string `json:"namespace" bson:"namespace"`
	RepositoryType    string `json:"repository_type" bson:"repository_type"`
	Status            int    `json:"status" bson:"status"`
	StatusDescription string `json:"status_description" bson:"status_description"`
	Description       string `json:"description" bson:"description"`
	IsPrivate         bool   `json:"is_private" bson:"is_private"`
	IsAutomated       bool   `json:"is_automated" bson:"is_automated"`
	StarCount         int64  `json:"star_count" bson:"star_count"`
	PullCount         int64  `json:"pull_count" bson:"pull_count"`
	LastUpdated       string `json:"last_updated" bson:"last_updated"`
	DateRegistered    string `json:"date_registered" bson:"date_registered"`
	CollaboratorCount int    `json:"collaborator_count " bson:"collaborator_count"`
	Affiliation       string `json:"affiliation" bson:"affiliation"`
	HubUser           string `json:"hub_user" bson:"hub_user"`
	HasStarred        bool   `json:"has_starred" bson:"has_starred"`
	FullDescription   string `json:"full_description" bson:"full_description"`
	Permissions       struct {
		Read  bool `json:"read" bson:"read"`
		Write bool `json:"write" bson:"write"`
		Admin bool `json:"admin" bson:"admin"`
	} `json:"permissions" bson:"permissions"`
	MediaTypes   []string `json:"media_types" bson:"media_types"`
	ContentTypes []string `json:"content_types" bson:"content_types"`
	// GraphBuiltAt is set by Stage II once ALL tags/images for this repo have
	// been inserted into Neo4j. On restart, repos with this field set are
	// skipped, enabling O(done) resume instead of full reprocessing.
	GraphBuiltAt string `json:"graph_built_at,omitempty" bson:"graph_built_at,omitempty"`
}

type Tag struct {
	RepositoryNamespace string `json:"repositories_namespace" bson:"repositories_namespace"`
	RepositoryName      string `json:"repositories_name" bson:"repositories_name"`

	Creator             int          `json:"creator" bson:"creator"`
	Id                  int          `json:"id" bson:"id"`
	Images              []ImageInTag `json:"images" bson:"images"`
	LastUpdated         string       `json:"last_updated" bson:"last_updated"`
	LastUpdater         int          `json:"last_updater" bson:"last_updater"`
	LastUpdaterUsername string       `json:"last_updater_username" bson:"last_updater_username"`
	Name                string       `json:"name" bson:"name"`
	FullSize            int64        `json:"full_size" bson:"full_size"`
	V2                  bool         `json:"v2" bson:"v2"`
	TagStatus           string       `json:"tag_status" bson:"tag_status"`
	TagLastPulled       string       `json:"tag_last_pulled" bson:"tag_last_pulled"`
	TagLastPushed       string       `json:"tag_last_pushed" bson:"tag_last_pushed"`
	MediaType           string       `json:"media_type" bson:"media_type"`
	ContentType         string       `json:"content_type" bson:"content_type"`
	Digest              string       `json:"digest" bson:"digest"`
}

type ImageInTag struct {
	Architecture string `json:"architecture" bson:"architecture"`
	Features     string `json:"features" bson:"features"`
	Variant      string `json:"variant" bson:"variant"`
	Digest       string `json:"digest" bson:"digest"`
	OS           string `json:"os" bson:"os"`
	OSFeatures   string `json:"os_features" bson:"os_features"`
	OSVersion    string `json:"os_version" bson:"os_version"`
	Size         int64  `json:"size" bson:"size"`
	Status       string `json:"status" bson:"status"`
	LastPulled   string `json:"last_pulled" bson:"last_pulled"`
	LastPushed   string `json:"last_pushed" bson:"last_pushed"`
}

type Image struct {
	Architecture string  `json:"architecture" bson:"architecture"`
	Features     string  `json:"features" bson:"features"`
	Variant      string  `json:"variant" bson:"variant"`
	Digest       string  `json:"digest" bson:"digest"`
	Layers       []Layer `json:"layers" bson:"layers"`
	OS           string  `json:"os" bson:"os"`
	OSFeatures   string  `json:"os_features" bson:"os_features"`
	OSVersion    string  `json:"os_version" bson:"os_version"`
	Size         int64   `json:"size" bson:"size"`
	Status       string  `json:"status" bson:"status"`
	LastPulled   string  `json:"last_pulled" bson:"last_pulled"`
	LastPushed   string  `json:"last_pushed" bson:"last_pushed"`
}

type Layer struct {
	Digest      string `json:"digest,omitempty" bson:"digest,omitempty"`
	Size        int64  `json:"size" bson:"size"`
	Instruction string `json:"instruction" bson:"instruction"`
}

type TagsPage struct {
	Count    int    `json:"count"`
	Next     string `json:"next"`
	Previous string `json:"previous"`
	Results  []*Tag `json:"results"`
}
