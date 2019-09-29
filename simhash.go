package main

import (
	"fmt"
	"hash/fnv"
	"strings"
	"sync"

	"github.com/yanyiwu/gojieba"
)

var (
	gjb *GoJieba
	one sync.Once
)

// WordWeight 词语权重
type WordWeight struct {
	Word   string
	Weight float64
}

// GoJieba 结巴分词接口
type GoJieba struct {
	C *gojieba.Jieba
}

func jiebaCutAll(x *gojieba.Jieba, rawStr *string) (words []string) {
	words = x.CutAll(*rawStr)
	return
}

func jiebaCut(x *gojieba.Jieba, rawStr *string, useHmm bool) (words []string) {
	words = x.Cut(*rawStr, useHmm)
	return
}

func jiebaCut4Search(x *gojieba.Jieba, rawStr *string, useHmm bool) (words []string) {
	words = x.CutForSearch(*rawStr, useHmm)
	return
}

func simhashFingerPrint(wordWeights []WordWeight) (fingerPrint []string, err error) {
	binaryWeights := make([]float64, 32)
	for _, ww := range wordWeights {
		bitHash := strHashBitCode(ww.Word)
		weights := calcWithWeight(bitHash, ww.Weight) //binary每个元素与weight的乘积结果数组
		binaryWeights, err = sliceInnerPlus(binaryWeights, weights)
		if err != nil {
			return
		}
	}
	fingerPrint = make([]string, 0)
	for _, b := range binaryWeights {
		if b > 0 { // bit 1
			fingerPrint = append(fingerPrint, "1")
		} else { // bit 0
			fingerPrint = append(fingerPrint, "0")
		}
	}
	return
}

func strHashBitCode(str string) string {
	h := fnv.New32a()
	h.Write([]byte(str))
	b := int64(h.Sum32())
	return fmt.Sprintf("%032b", b)
}

func calcWithWeight(bitHash string, weight float64) []float64 {
	bitHashs := strings.Split(bitHash, "")
	binarys := make([]float64, 0)
	for _, bit := range bitHashs {
		if bit == "0" {
			binarys = append(binarys, float64(-1)*weight)
		} else {
			binarys = append(binarys, float64(weight))
		}
	}
	return binarys
}

func sliceInnerPlus(arr1, arr2 []float64) (dstArr []float64, err error) {
	dstArr = make([]float64, len(arr1), len(arr1))
	if arr1 == nil || arr2 == nil {
		Error.Println("sliceInnerPlus array nil")
		return
	}
	if len(arr1) != len(arr2) {
		Error.Printf("sliceInnerPlus array Length NOT match, %v != %v\n", len(arr1), len(arr2))
		return
	}
	for i, v1 := range arr1 {
		dstArr[i] = v1 + arr2[i]
	}
	return
}

func hammingDistance(arr1, arr2 []string) int {
	count := 0
	for i, v1 := range arr1 {
		if v1 != arr2[i] {
			count++
		}
	}
	return count
}

func newGoJieba() *GoJieba {
	one.Do(func() {
		gjb = &GoJieba{
			C: gojieba.NewJieba(),
			//equals with x := NewJieba(DICT_PATH, HMM_PATH, USER_DICT_PATH)
		}
	})
	return gjb
}

func (jb *GoJieba) close() {
	jb.C.Free()
}

func simHashSimilar(srcWordWeighs, dstWordWeights []WordWeight) (distance int, err error) {
	srcFingerPrint, err := simhashFingerPrint(srcWordWeighs)
	if err != nil {
		return
	}
	Debug.Println("srcFingerPrint: ", srcFingerPrint)
	dstFingerPrint, err := simhashFingerPrint(dstWordWeights)
	if err != nil {
		return
	}
	Debug.Println("dstFingerPrint: ", dstFingerPrint)
	distance = hammingDistance(srcFingerPrint, dstFingerPrint)
	return
}

// GetSimHashSimilar 获取相似性
func GetSimHashSimilar(srcStr string, dstStr string) int {
	g := newGoJieba()
	srcWordsWeight := g.C.ExtractWithWeight(srcStr, 30)
	dstWordsWeight := g.C.ExtractWithWeight(dstStr, 30)
	Debug.Printf("SrcWordsWeight : %v\n", srcWordsWeight)
	Debug.Printf("DstWordsWeight : %v\n", dstWordsWeight)
	srcWords := make([]WordWeight, len(srcWordsWeight))
	dstWords := make([]WordWeight, len(dstWordsWeight))
	Debug.Println("1")
	for i, ww := range srcWordsWeight {
		word := WordWeight{Word: ww.Word, Weight: ww.Weight}
		srcWords[i] = word
	}
	Debug.Println("2")
	for i, ww := range dstWordsWeight {
		word := WordWeight{Word: ww.Word, Weight: ww.Weight}
		dstWords[i] = word
	}
	Debug.Printf("SrcWords : %v\n", srcWords)
	Debug.Printf("DstWords : %v\n", dstWords)
	distance, err := simHashSimilar(srcWords, dstWords)
	if err != nil {
		Error.Printf("[E] SimHashSimilar Failed: %v\n", err.Error())
		return 0
	}
	Debug.Printf("SimHashSimilar distance: %v\n", distance)
	g.close()
	return distance
}
