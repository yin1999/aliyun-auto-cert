package dns

import (
	"auto-cert/pkg/ref"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"

	aliDns "github.com/alibabacloud-go/alidns-20150109/v4/client"
)

const (
	textRecordType = "TXT"
)

type Client struct {
	c *aliDns.Client
}

func CreateClient(cfg *openapi.Config) (*Client, error) {
	c, err := aliDns.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{c}, nil
}

func (c *Client) AddOrSetTextRecord(domain, rr, value string) error {
	record, err := c.getTextRecord(domain, rr)
	if err != nil {
		return err
	}
	if record == nil {
		// create
		req := &aliDns.AddDomainRecordRequest{
			DomainName: ref.GetPointer(domain),
			RR:         ref.GetPointer(rr),
			Type:       ref.GetPointer(textRecordType),
			Value:      ref.GetPointer(value),
		}

		_, err = c.c.AddDomainRecordWithOptions(req, &util.RuntimeOptions{})
	} else {
		// update
		req := &aliDns.UpdateDomainRecordRequest{
			RecordId: ref.GetPointer(record.RecordId),
			RR:       ref.GetPointer(rr),
			Type:     ref.GetPointer(textRecordType),
			Value:    ref.GetPointer(value),
		}

		_, err = c.c.UpdateDomainRecordWithOptions(req, &util.RuntimeOptions{})
	}
	return err
}

type record struct {
	DomainName string
	Priority   int64
	RR         string
	RecordId   string
	Status     string
	TTL        int64
	Type       string
	Value      string
	Weight     int32
}

func (c *Client) getTextRecord(domain, rr string) (*record, error) {
	req := &aliDns.DescribeDomainRecordsRequest{
		DomainName: ref.GetPointer(domain),
		RRKeyWord:  ref.GetPointer(rr),
		Type:       ref.GetPointer(textRecordType),
		PageSize:   ref.GetPointer(int64(500)),
	}

	resp, err := c.c.DescribeDomainRecordsWithOptions(req, &util.RuntimeOptions{})
	if err != nil {
		return nil, err
	}

	records := ref.DerefOrDefault(resp.Body.DomainRecords).Record

	var rec *aliDns.DescribeDomainRecordsResponseBodyDomainRecordsRecord
	for _, r := range records {
		if ref.DerefOrDefault(r.RR) == rr {
			rec = r
			break
		}
	}

	if rec == nil {
		return nil, nil
	}

	return &record{
		DomainName: ref.DerefOrDefault(rec.DomainName),
		Priority:   ref.DerefOrDefault(rec.Priority),
		RR:         ref.DerefOrDefault(rec.RR),
		RecordId:   ref.DerefOrDefault(rec.RecordId),
		Status:     ref.DerefOrDefault(rec.Status),
		TTL:        ref.DerefOrDefault(rec.TTL),
		Type:       ref.DerefOrDefault(rec.Type),
		Value:      ref.DerefOrDefault(rec.Value),
		Weight:     ref.DerefOrDefault(rec.Weight),
	}, nil
}

func (c *Client) DeleteTextRecord(domain, rr string) error {
	record, err := c.getTextRecord(domain, rr)
	// no record to delete or error
	if err != nil || record == nil {
		return err
	}

	req := &aliDns.DeleteDomainRecordRequest{
		RecordId: ref.GetPointer(record.RecordId),
	}

	_, err = c.c.DeleteDomainRecordWithOptions(req, &util.RuntimeOptions{})
	return err
}
