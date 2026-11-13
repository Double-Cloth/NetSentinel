package rule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// CanonicalJSON 按对象键排序编码，保留数组顺序并关闭 HTML 转义。
func CanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// checkJSON 在解码前拒绝重复键、额外根值与过深输入。
func checkJSON(raw []byte) error {
	if len(raw) > 64*1024 || !utf8.Valid(raw) {
		return fmt.Errorf("JSON 大小或 UTF-8 编码无效")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := walkJSON(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("JSON 根值后存在额外内容")
	}
	return nil
}

func walkJSON(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return fmt.Errorf("JSON 嵌套过深")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	keys := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || keys[key] {
				return fmt.Errorf("JSON 对象键重复或无效")
			}
			keys[key] = true
		}
		if err := walkJSON(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
