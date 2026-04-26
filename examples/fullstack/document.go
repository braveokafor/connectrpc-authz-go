package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"connectrpc.com/connect"

	documentv1 "github.com/braveokafor/connectrpc-authz-go/examples/fullstack/gen/document/v1"
	"github.com/braveokafor/connectrpc-authz-go/examples/fullstack/gen/document/v1/documentv1connect"
)

type document struct {
	ID      string
	Title   string
	Content string
}

// DocumentServer implements documentv1connect.DocumentServiceHandler.
type DocumentServer struct {
	documentv1connect.UnimplementedDocumentServiceHandler
	docs sync.Map
	seq  atomic.Int64
}

func NewDocumentServer() *DocumentServer {
	s := &DocumentServer{}
	s.docs.Store("doc-1", &document{ID: "doc-1", Title: "Welcome", Content: "Hello from the document service."})
	s.docs.Store("doc-2", &document{ID: "doc-2", Title: "Getting Started", Content: "This is a guide to getting started."})
	s.docs.Store("doc-3", &document{ID: "doc-3", Title: "Architecture", Content: "Overview of the system architecture."})
	s.seq.Store(3)
	return s
}

func (s *DocumentServer) GetDocument(
	ctx context.Context,
	req *connect.Request[documentv1.GetDocumentRequest],
) (*connect.Response[documentv1.GetDocumentResponse], error) {
	v, ok := s.docs.Load(req.Msg.Id)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("document %q not found", req.Msg.Id))
	}
	doc := v.(*document)
	return connect.NewResponse(&documentv1.GetDocumentResponse{
		Id: doc.ID, Title: doc.Title, Content: doc.Content,
	}), nil
}

func (s *DocumentServer) CreateDocument(
	ctx context.Context,
	req *connect.Request[documentv1.CreateDocumentRequest],
) (*connect.Response[documentv1.CreateDocumentResponse], error) {
	id := fmt.Sprintf("doc-%d", s.seq.Add(1))
	s.docs.Store(id, &document{ID: id, Title: req.Msg.Title, Content: req.Msg.Content})
	return connect.NewResponse(&documentv1.CreateDocumentResponse{Id: id}), nil
}

func (s *DocumentServer) DeleteDocument(
	ctx context.Context,
	req *connect.Request[documentv1.DeleteDocumentRequest],
) (*connect.Response[documentv1.DeleteDocumentResponse], error) {
	if _, ok := s.docs.Load(req.Msg.Id); !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("document %q not found", req.Msg.Id))
	}
	s.docs.Delete(req.Msg.Id)
	return connect.NewResponse(&documentv1.DeleteDocumentResponse{}), nil
}
