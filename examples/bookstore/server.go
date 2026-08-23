package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/brianvoe/gofakeit/v7"
	"google.golang.org/protobuf/types/known/emptypb"

	bookstorev1 "github.com/braveokafor/connectrpc-authz-go/examples/bookstore/gen/bookstore/v1"
)

type BookstoreServer struct {
	mu    sync.Mutex
	books map[int64]*bookstorev1.Book
	seq   int64
}

func NewBookstoreServer() *BookstoreServer {
	s := &BookstoreServer{books: map[int64]*bookstorev1.Book{}}
	g := gofakeit.New(0)
	for range 20 {
		s.add(&bookstorev1.CreateBookRequest{Title: g.BookTitle(), Author: g.BookAuthor(), Shelf: int64(g.Number(1, 3))}, "seed")
	}
	return s
}

func (s *BookstoreServer) add(req *bookstorev1.CreateBookRequest, owner string) *bookstorev1.Book {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	book := &bookstorev1.Book{
		Id: s.seq, Title: req.GetTitle(), Author: req.GetAuthor(), Shelf: req.GetShelf(), Owner: owner,
	}
	s.books[book.Id] = book
	return book
}

func (s *BookstoreServer) GetBook(_ context.Context, req *connect.Request[bookstorev1.GetBookRequest]) (*connect.Response[bookstorev1.Book], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	book, ok := s.books[req.Msg.GetId()]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("book %d not found", req.Msg.GetId()))
	}
	return connect.NewResponse(book), nil
}

func (s *BookstoreServer) ListBooks(_ context.Context, req *connect.Request[bookstorev1.ListBooksRequest]) (*connect.Response[bookstorev1.ListBooksResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := &bookstorev1.ListBooksResponse{}
	for _, book := range s.books {
		if book.GetShelf() == req.Msg.GetShelf() {
			resp.Books = append(resp.Books, book)
		}
	}
	return connect.NewResponse(resp), nil
}

func (s *BookstoreServer) CreateBook(ctx context.Context, req *connect.Request[bookstorev1.CreateBookRequest]) (*connect.Response[bookstorev1.Book], error) {
	return connect.NewResponse(s.add(req.Msg, getSubject(ctx))), nil
}

func (s *BookstoreServer) DeleteBook(_ context.Context, req *connect.Request[bookstorev1.DeleteBookRequest]) (*connect.Response[emptypb.Empty], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.books[req.Msg.GetId()]; !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("book %d not found", req.Msg.GetId()))
	}
	delete(s.books, req.Msg.GetId())
	return connect.NewResponse(&emptypb.Empty{}), nil
}

func (s *BookstoreServer) ImportBooks(ctx context.Context, stream *connect.ClientStream[bookstorev1.CreateBookRequest]) (*connect.Response[bookstorev1.ImportSummary], error) {
	owner := getSubject(ctx)
	var created int32
	for stream.Receive() {
		s.add(stream.Msg(), owner)
		created++
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	return connect.NewResponse(&bookstorev1.ImportSummary{Created: created}), nil
}

func (s *BookstoreServer) WatchAuction(ctx context.Context, req *connect.Request[bookstorev1.WatchAuctionRequest], stream *connect.ServerStream[bookstorev1.AuctionUpdate]) error {
	high := 100.0
	for i := 1; i <= 3; i++ {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(300 * time.Millisecond):
		}
		high += 25
		update := &bookstorev1.AuctionUpdate{Book: req.Msg.GetBook(), HighBid: high, Bidder: fmt.Sprintf("paddle-%d", i)}
		if err := stream.Send(update); err != nil {
			return err
		}
	}
	return nil
}

func (s *BookstoreServer) Bid(ctx context.Context, stream *connect.BidiStream[bookstorev1.BidRequest, bookstorev1.AuctionUpdate]) error {
	high := 0.0
	bidder := ""
	for {
		req, err := stream.Receive()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if req.GetAmount() > high {
			high, bidder = req.GetAmount(), getSubject(ctx)
		}
		if err := stream.Send(&bookstorev1.AuctionUpdate{Book: req.GetBook(), HighBid: high, Bidder: bidder}); err != nil {
			return err
		}
	}
}
