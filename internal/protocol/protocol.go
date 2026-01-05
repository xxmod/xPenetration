package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// 消息类型定义
const (
	MsgTypeAuth          uint8 = 1  // 认证请求
	MsgTypeAuthResp      uint8 = 2  // 认证响应
	MsgTypeTunnelConfig  uint8 = 3  // 隧道配置下发
	MsgTypeNewConnection uint8 = 4  // 新连接通知
	MsgTypeData          uint8 = 5  // 数据传输
	MsgTypeHeartbeat     uint8 = 6  // 心跳
	MsgTypeHeartbeatAck  uint8 = 7  // 心跳确认
	MsgTypeDisconnect    uint8 = 8  // 断开连接
	MsgTypeError         uint8 = 9  // 错误消息
	MsgTypeConnReady     uint8 = 10 // 连接就绪
	MsgTypeUDPData       uint8 = 11 // UDP数据传输
)

// Message 通用消息结构
type Message struct {
	Type    uint8  `json:"type"`
	Payload []byte `json:"payload"`
}

// AuthRequest 认证请求
type AuthRequest struct {
	SecretKey  string `json:"secret_key"`
	ClientName string `json:"client_name"`
	Version    string `json:"version"`
}

// AuthResponse 认证响应
type AuthResponse struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	ClientID string `json:"client_id"`
}

// TunnelConfig 隧道配置
type TunnelConfig struct {
	Tunnels []Tunnel `json:"tunnels"`
}

// Tunnel 单个隧道配置
type Tunnel struct {
	Name       string `json:"name" yaml:"name"`
	ClientPort int    `json:"client_port" yaml:"client_port"` // 客户端本地端口
	ServerPort int    `json:"server_port" yaml:"server_port"` // 服务端暴露端口
	Protocol   string `json:"protocol" yaml:"protocol"`       // tcp/udp
}

// NewConnection 新连接通知
type NewConnection struct {
	ConnID     string `json:"conn_id"`
	TunnelName string `json:"tunnel_name"`
	ClientPort int    `json:"client_port"`
	RemoteAddr string `json:"remote_addr"`
}

// ConnReady 连接就绪通知
type ConnReady struct {
	ConnID  string `json:"conn_id"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// DataMessage 数据消息
type DataMessage struct {
	ConnID string `json:"conn_id"`
	Data   []byte `json:"data"`
}

// DisconnectMessage 断开连接消息
type DisconnectMessage struct {
	ConnID string `json:"conn_id"`
	Reason string `json:"reason"`
}

// ErrorMessage 错误消息
type ErrorMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Heartbeat 心跳消息
type Heartbeat struct {
	Timestamp int64 `json:"timestamp"`
}

// UDPDataMessage UDP数据消息（通过TCP隧道传输）
type UDPDataMessage struct {
	TunnelName string `json:"tunnel_name"` // 隧道名称
	ClientPort int    `json:"client_port"` // 客户端本地端口
	RemoteAddr string `json:"remote_addr"` // 远程地址（用于响应）
	Data       []byte `json:"data"`        // UDP数据
}

// EncodeUDPDataMessage 二进制编码UDP数据消息（高性能）
// 格式: [1字节隧道名长度][隧道名][2字节端口][1字节地址长度][地址][数据]
func EncodeUDPDataMessage(tunnelName string, clientPort int, remoteAddr string, data []byte) []byte {
	tunnelNameBytes := []byte(tunnelName)
	remoteAddrBytes := []byte(remoteAddr)

	totalLen := 1 + len(tunnelNameBytes) + 2 + 1 + len(remoteAddrBytes) + len(data)
	buf := make([]byte, totalLen)

	offset := 0
	buf[offset] = byte(len(tunnelNameBytes))
	offset++
	copy(buf[offset:], tunnelNameBytes)
	offset += len(tunnelNameBytes)
	binary.BigEndian.PutUint16(buf[offset:], uint16(clientPort))
	offset += 2
	buf[offset] = byte(len(remoteAddrBytes))
	offset++
	copy(buf[offset:], remoteAddrBytes)
	offset += len(remoteAddrBytes)
	copy(buf[offset:], data)

	return buf
}

// DecodeUDPDataMessageBinary 二进制解码UDP数据消息（高性能）
func DecodeUDPDataMessageBinary(payload []byte) (*UDPDataMessage, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("payload too short")
	}

	offset := 0
	tunnelNameLen := int(payload[offset])
	offset++

	if len(payload) < offset+tunnelNameLen+3 {
		return nil, fmt.Errorf("payload too short for tunnel name")
	}
	tunnelName := string(payload[offset : offset+tunnelNameLen])
	offset += tunnelNameLen

	clientPort := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2

	remoteAddrLen := int(payload[offset])
	offset++

	if len(payload) < offset+remoteAddrLen {
		return nil, fmt.Errorf("payload too short for remote addr")
	}
	remoteAddr := string(payload[offset : offset+remoteAddrLen])
	offset += remoteAddrLen

	data := payload[offset:]

	return &UDPDataMessage{
		TunnelName: tunnelName,
		ClientPort: clientPort,
		RemoteAddr: remoteAddr,
		Data:       data,
	}, nil
}

// EncodeMessage 编码消息
func EncodeMessage(msg *Message) ([]byte, error) {
	// 消息格式: [1字节类型][4字节长度][payload]
	payloadLen := len(msg.Payload)
	buf := make([]byte, 5+payloadLen)
	buf[0] = msg.Type
	binary.BigEndian.PutUint32(buf[1:5], uint32(payloadLen))
	copy(buf[5:], msg.Payload)
	return buf, nil
}

// DecodeMessage 解码消息
func DecodeMessage(conn net.Conn) (*Message, error) {
	// 读取消息头
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	msgType := header[0]
	payloadLen := binary.BigEndian.Uint32(header[1:5])

	// 限制最大消息大小为10MB
	if payloadLen > 10*1024*1024 {
		return nil, fmt.Errorf("message too large: %d bytes", payloadLen)
	}

	// 读取payload
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, err
		}
	}

	return &Message{
		Type:    msgType,
		Payload: payload,
	}, nil
}

// SendMessage 发送消息
func SendMessage(conn net.Conn, msg *Message) error {
	data, err := EncodeMessage(msg)
	if err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}

// NewAuthRequest 创建认证请求消息
func NewAuthRequest(secretKey, clientName string) (*Message, error) {
	req := AuthRequest{
		SecretKey:  secretKey,
		ClientName: clientName,
		Version:    "1.0.0",
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgTypeAuth,
		Payload: payload,
	}, nil
}

// NewAuthResponse 创建认证响应消息
func NewAuthResponse(success bool, message, clientID string) (*Message, error) {
	resp := AuthResponse{
		Success:  success,
		Message:  message,
		ClientID: clientID,
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgTypeAuthResp,
		Payload: payload,
	}, nil
}

// NewTunnelConfig 创建隧道配置消息
func NewTunnelConfig(tunnels []Tunnel) (*Message, error) {
	config := TunnelConfig{
		Tunnels: tunnels,
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgTypeTunnelConfig,
		Payload: payload,
	}, nil
}

// NewConnectionMessage 创建新连接通知消息
func NewConnectionMessage(connID, tunnelName string, clientPort int, remoteAddr string) (*Message, error) {
	nc := NewConnection{
		ConnID:     connID,
		TunnelName: tunnelName,
		ClientPort: clientPort,
		RemoteAddr: remoteAddr,
	}
	payload, err := json.Marshal(nc)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgTypeNewConnection,
		Payload: payload,
	}, nil
}

// NewConnReadyMessage 创建连接就绪消息
func NewConnReadyMessage(connID string, success bool, message string) (*Message, error) {
	cr := ConnReady{
		ConnID:  connID,
		Success: success,
		Message: message,
	}
	payload, err := json.Marshal(cr)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgTypeConnReady,
		Payload: payload,
	}, nil
}

// NewDataMessage 创建数据传输消息
func NewDataMessage(connID string, data []byte) (*Message, error) {
	dm := DataMessage{
		ConnID: connID,
		Data:   data,
	}
	payload, err := json.Marshal(dm)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgTypeData,
		Payload: payload,
	}, nil
}

// NewDisconnectMessage 创建断开连接消息
func NewDisconnectMessage(connID, reason string) (*Message, error) {
	dm := DisconnectMessage{
		ConnID: connID,
		Reason: reason,
	}
	payload, err := json.Marshal(dm)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgTypeDisconnect,
		Payload: payload,
	}, nil
}

// NewHeartbeat 创建心跳消息
func NewHeartbeat(timestamp int64) (*Message, error) {
	hb := Heartbeat{
		Timestamp: timestamp,
	}
	payload, err := json.Marshal(hb)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgTypeHeartbeat,
		Payload: payload,
	}, nil
}

// NewHeartbeatAck 创建心跳确认消息
func NewHeartbeatAck(timestamp int64) (*Message, error) {
	hb := Heartbeat{
		Timestamp: timestamp,
	}
	payload, err := json.Marshal(hb)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgTypeHeartbeatAck,
		Payload: payload,
	}, nil
}

// NewErrorMessage 创建错误消息
func NewErrorMessage(code int, message string) (*Message, error) {
	em := ErrorMessage{
		Code:    code,
		Message: message,
	}
	payload, err := json.Marshal(em)
	if err != nil {
		return nil, err
	}
	return &Message{
		Type:    MsgTypeError,
		Payload: payload,
	}, nil
}

// ParseAuthRequest 解析认证请求
func ParseAuthRequest(payload []byte) (*AuthRequest, error) {
	var req AuthRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// ParseAuthResponse 解析认证响应
func ParseAuthResponse(payload []byte) (*AuthResponse, error) {
	var resp AuthResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseTunnelConfig 解析隧道配置
func ParseTunnelConfig(payload []byte) (*TunnelConfig, error) {
	var config TunnelConfig
	if err := json.Unmarshal(payload, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// ParseNewConnection 解析新连接通知
func ParseNewConnection(payload []byte) (*NewConnection, error) {
	var nc NewConnection
	if err := json.Unmarshal(payload, &nc); err != nil {
		return nil, err
	}
	return &nc, nil
}

// ParseConnReady 解析连接就绪消息
func ParseConnReady(payload []byte) (*ConnReady, error) {
	var cr ConnReady
	if err := json.Unmarshal(payload, &cr); err != nil {
		return nil, err
	}
	return &cr, nil
}

// ParseDataMessage 解析数据消息
func ParseDataMessage(payload []byte) (*DataMessage, error) {
	var dm DataMessage
	if err := json.Unmarshal(payload, &dm); err != nil {
		return nil, err
	}
	return &dm, nil
}

// ParseDisconnectMessage 解析断开连接消息
func ParseDisconnectMessage(payload []byte) (*DisconnectMessage, error) {
	var dm DisconnectMessage
	if err := json.Unmarshal(payload, &dm); err != nil {
		return nil, err
	}
	return &dm, nil
}

// ParseHeartbeat 解析心跳消息
func ParseHeartbeat(payload []byte) (*Heartbeat, error) {
	var hb Heartbeat
	if err := json.Unmarshal(payload, &hb); err != nil {
		return nil, err
	}
	return &hb, nil
}

// ParseErrorMessage 解析错误消息
func ParseErrorMessage(payload []byte) (*ErrorMessage, error) {
	var em ErrorMessage
	if err := json.Unmarshal(payload, &em); err != nil {
		return nil, err
	}
	return &em, nil
}

// NewUDPDataMessage 创建UDP数据消息（使用二进制编码提高性能）
func NewUDPDataMessage(tunnelName string, clientPort int, remoteAddr string, data []byte) (*Message, error) {
	payload := EncodeUDPDataMessage(tunnelName, clientPort, remoteAddr, data)
	return &Message{
		Type:    MsgTypeUDPData,
		Payload: payload,
	}, nil
}

// ParseUDPDataMessage 解析UDP数据消息（使用二进制解码提高性能）
func ParseUDPDataMessage(payload []byte) (*UDPDataMessage, error) {
	return DecodeUDPDataMessageBinary(payload)
}
