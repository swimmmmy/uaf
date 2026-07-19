#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "viz.h"

typedef struct Laptop {
    char owner[16];
    int  asset_no;
} Laptop;

int main(void) {
    viz_title("my_uaf - WHS 노트북 반납 후 재대여", "반납된 노트북 자리가 다른 사람한테 넘어가면?");

    viz_step("멘티 A가 노트북을 대여한다");
    Laptop *rented = malloc(sizeof(Laptop));
    strcpy(rented->owner, "Sadie");
    rented->asset_no = 12;
    viz_cell("rented", rented, rented->owner, VZ_LIVE);

    viz_step("반납 처리 (free) - 근데 최근 대여 기록 포인터는 안 지웠다");
    Laptop *last_rental_record = rented;
    free(rented);
    viz_cell("last_rental_record", last_rental_record, "??? 반납됨", VZ_DANGLE);

    viz_step("다른 멘티 B가 같은 자리를 새로 대여한다");
    Laptop *new_rental = malloc(sizeof(Laptop));
    strcpy(new_rental->owner, "Mingyo");
    new_rental->asset_no = 12;

    viz_step("최근 대여 기록에서 '누가 빌렸는지' 다시 조회한다 = UAF");
    printf("최근 대여 기록 조회: %s (asset=%d)\n", last_rental_record->owner, last_rental_record->asset_no);
    viz_cell("last_rental_record->owner", last_rental_record, last_rental_record->owner, VZ_PLANT);

    if (new_rental == last_rental_record)
        viz_bad("반납 기록이 남(멘티 B)의 이름을 보여주고 있다! 자산 관리에 혼선.");

    free(new_rental);
    return 0;
}
