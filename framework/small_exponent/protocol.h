#define BLOCK_LENGTH 16

enum message_type {
  CHALLENGE,
  SOLUTION,
  SOLUTION_REP};

typedef struct message {
  enum message_type type;
  union {
    struct {
      unsigned char key[3][256];
      unsigned char ch[3][256];
    } challenge;
    struct {
      unsigned char m[256];
    } solution;
    struct {
      int rep; // 0 ok; 1 wrong
    } solution_rep;
  };
} message;
