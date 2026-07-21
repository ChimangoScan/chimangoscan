package myutils

import "time"

// 测试用户testuser Testpassw0rd
type User struct {
	UID              string    `json:"uid" bson:"uid"` // 随机数->sha256->查重
	Username         string    `json:"username" bson:"username"`
	Password         string    `json:"password" bson:"password"` // password的SHA256哈希
	FullName         string    `json:"fullname" bson:"fullname"`
	FirstName        string    `json:"firstname" bson:"firstname"`
	LastName         string    `json:"lastname" bson:"lastname"`
	Email            string    `json:"email" bson:"email"`
	Phone            string    `json:"phone" bson:"phone"`
	RegistrationTime time.Time `json:"registration_time" bson:"registration_time"`
	LastLoginTime    time.Time `json:"last_login_time" bson:"last_login_time"`
	Status           int       `json:"status" bson:"status"` // 0: to be activated, 1: activated, 2: banned
	Type             int       `json:"type" bson:"type"`     // 0: anonymous, 1: user, 2: admin, 3: superadmin
	// Secret           string    `json:"secret" bson:"secret"` // 运行时生成，用于加解密jwt，想错了，这个secret应该是服务端自己的
}
