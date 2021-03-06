/*
 *  Copyright 2020 the original author or authors.
 *
 * This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package guru.sfg.brewery.web.controllers.api;

import guru.sfg.brewery.security.perms.PreAuthorizeBeerCreate;
import guru.sfg.brewery.security.perms.PreAuthorizeBeerDelete;
import guru.sfg.brewery.security.perms.PreAuthorizeBeerRead;
import guru.sfg.brewery.security.perms.PreAuthorizeBeerUpdate;
import guru.sfg.brewery.services.BeerService;
import guru.sfg.brewery.web.model.BeerDto;
import guru.sfg.brewery.web.model.BeerPagedList;
import guru.sfg.brewery.web.model.BeerStyleEnum;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.ConstraintViolationException;
import javax.validation.Valid;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@RequestMapping("/api/v1/")
@RestController
public class BeerRestController {

    private static final Integer DEFAULT_PAGE_NUMBER = 0;
    private static final Integer DEFAULT_PAGE_SIZE = 25;

    private final BeerService beerService;

    @PreAuthorizeBeerRead
    @GetMapping(produces = {"application/json"}, path = "beer")
    public @NotNull ResponseEntity<BeerPagedList> listBeers(
            @Nullable @RequestParam(value = "pageNumber", required = false) Integer pageNumber,
            @Nullable @RequestParam(value = "pageSize", required = false) Integer pageSize,
            @Nullable @RequestParam(value = "beerName", required = false) String beerName,
            @Nullable @RequestParam(value = "beerStyle", required = false) BeerStyleEnum beerStyle,
            @Nullable @RequestParam(value = "showInventoryOnHand", required = false) Boolean showInventoryOnHand) {
        log.debug("Listing Beers");

        if (showInventoryOnHand == null) {
            showInventoryOnHand = false;
        }

        if (pageNumber == null || pageNumber < 0) {
            pageNumber = DEFAULT_PAGE_NUMBER;
        }

        if (pageSize == null || pageSize < 1) {
            pageSize = DEFAULT_PAGE_SIZE;
        }

        BeerPagedList beerList = beerService.listBeers(beerName, beerStyle,
                PageRequest.of(pageNumber, pageSize), showInventoryOnHand);

        return new ResponseEntity<>(beerList, HttpStatus.OK);
    }

    @PreAuthorizeBeerRead
    @GetMapping(path = {"beer/{beerId}"}, produces = {"application/json"})
    public @NotNull ResponseEntity<BeerDto> getBeerById(
            @Nullable @PathVariable("beerId") UUID beerId,
            @Nullable @RequestParam(value = "showInventoryOnHand", required = false) Boolean showInventoryOnHand) {
        log.debug("Get Request for BeerId: " + beerId);

        if (showInventoryOnHand == null) {
            showInventoryOnHand = false;
        }

        return new ResponseEntity<>(beerService.findBeerById(beerId, showInventoryOnHand), HttpStatus.OK);
    }

    @PreAuthorizeBeerRead
    @GetMapping(path = {"beerUpc/{upc}"}, produces = {"application/json"})
    public @NotNull ResponseEntity<BeerDto> getBeerByUpc(@Nullable @PathVariable("upc") String upc) {
        return new ResponseEntity<>(beerService.findBeerByUpc(upc), HttpStatus.OK);
    }

    @PreAuthorizeBeerCreate
    @PostMapping(path = "beer")
    public @NotNull ResponseEntity<Void> saveNewBeer(@NotNull @Valid @RequestBody BeerDto beerDto) {
        BeerDto savedDto = beerService.saveBeer(beerDto);
        HttpHeaders httpHeaders = new HttpHeaders();

        //todo hostname for uri
        httpHeaders.add("Location", "/api/v1/beer_service/" + savedDto.getId().toString());

        return new ResponseEntity<>(httpHeaders, HttpStatus.CREATED);
    }

    @PreAuthorizeBeerUpdate
    @PutMapping(path = {"beer/{beerId}"}, produces = {"application/json"})
    public @NotNull ResponseEntity<Void> updateBeer(
            @NotNull @PathVariable("beerId") UUID beerId,
            @NotNull @Valid @RequestBody BeerDto beerDto) {

        beerService.updateBeer(beerId, beerDto);

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PreAuthorizeBeerDelete
    @DeleteMapping({"beer/{beerId}"})
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteBeer(@Nullable @PathVariable("beerId") UUID beerId) {
        beerService.deleteById(beerId);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @NotNull ResponseEntity<List<String>> badRequestHandler(@NotNull ConstraintViolationException e) {
        List<String> errors = new ArrayList<>(e.getConstraintViolations().size());

        e.getConstraintViolations().forEach(constraintViolation -> errors.add(
                constraintViolation.getPropertyPath().toString() + " : " + constraintViolation.getMessage()));

        return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
    }

}
